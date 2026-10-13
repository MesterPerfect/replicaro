package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/local/replicaro/database"
	"github.com/local/replicaro/desktop"
	"github.com/local/replicaro/engines"
	"github.com/local/replicaro/integrations"
	"github.com/local/replicaro/models"
	"github.com/local/replicaro/vaultidentity"
	"github.com/local/replicaro/vaultlock"
	"github.com/local/replicaro/vaultprofile"
)

const rcloneAuthSessionLifetime = 15 * time.Minute

type rcloneAuthEntry struct {
	flow       *engines.RcloneAuthorizationFlow
	provider   string
	expiresAt  time.Time
	sessionCtx context.Context
	cancel     context.CancelFunc
	cleanupErr error
	finalUse   bool
	worker     *rcloneAuthWorker
	relay      io.Closer
	generation uint64
}

type rcloneAuthRelayHandle struct {
	closer io.Closer
	once   sync.Once
	err    error
}

func (handle *rcloneAuthRelayHandle) Close() error {
	if handle == nil {
		return nil
	}
	handle.once.Do(func() {
		if handle.closer == nil {
			handle.err = fmt.Errorf("rclone authorization callback relay is absent")
			return
		}
		handle.err = handle.closer.Close()
	})
	return handle.err
}

type rcloneAuthWorker struct {
	mu           sync.Mutex
	cancel       context.CancelFunc
	done         chan struct{}
	flow         *engines.RcloneAuthorizationFlow
	err          error
	generation   uint64
	urlHandedOff bool
}

func (worker *rcloneAuthWorker) result() (*engines.RcloneAuthorizationFlow, error, bool) {
	if worker == nil {
		return nil, nil, true
	}
	select {
	case <-worker.done:
		worker.mu.Lock()
		defer worker.mu.Unlock()
		return worker.flow, worker.err, true
	default:
		return nil, nil, false
	}
}

func rcloneAuthWorkerFailure(err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("native rclone authorization worker returned no flow")
}

// A sign-in whose rclone step failed (a refused or failed token exchange, for
// example) reports one of these instead of "unavailable", so the page says the
// sign-in failed rather than that it was cancelled or expired. They carry the
// same fixed texts the start and continue requests use.
var (
	errRcloneAuthStartFailed    = errors.New("native rclone authorization could not be started")
	errRcloneAuthContinueFailed = errors.New("native rclone authorization could not be continued")
)

func rcloneAuthTransitionFailure(worker *rcloneAuthWorker) error {
	if worker.generation > 1 {
		return errRcloneAuthContinueFailed
	}
	return errRcloneAuthStartFailed
}

type rcloneAuthStore struct {
	mu       sync.Mutex
	sessions map[string]rcloneAuthEntry
	start    func(context.Context, string, string, func(string)) (*engines.RcloneAuthorizationFlow, error)
	// openPage opens the sign-in link in the user's browser once rclone has
	// printed it. It's nil when Replicaro mustn't open a browser: with
	// --rclone-auth-no-open-browser (or --headless) and in the Docker package.
	// The link goes back to the UI either way, so a user whose browser didn't
	// open can still finish signing in.
	openPage            func(string) error
	now                 func() time.Time
	lifetime            time.Duration
	retryInterval       time.Duration
	timer               *time.Timer
	shutdown            bool
	starting            sync.WaitGroup
	finalUses           sync.WaitGroup
	cleanups            sync.WaitGroup
	shutdownCleanupErrs []error
	beforeHandoff       func(string)
	relayFactory        rcloneAuthRelayFactory
}

type rcloneAuthStatus struct {
	SessionID        string                      `json:"sessionId"`
	Provider         string                      `json:"provider"`
	Status           string                      `json:"status"`
	Question         *engines.RcloneAuthQuestion `json:"question,omitempty"`
	AuthorizationURL string                      `json:"authorizationUrl,omitempty"`
}

type rcloneApplicationOutcome struct {
	Activation   engines.RcloneConfigActivation `json:"activation"`
	Attached     bool                           `json:"attached"`
	Usable       *bool                          `json:"usable,omitempty"`
	FailureStage rcloneApplicationFailureStage  `json:"failureStage,omitempty"`
	// Only a cloud sign-in apply that saved the new login sets this, when a
	// cleanup after the save did not finish. Creation and connection copy
	// just the lifecycle fields above into their own response and report
	// their issues there.
	foregroundOutcome
}

type rcloneApplicationFailureStage string

const (
	rcloneFailureAdmission                 rcloneApplicationFailureStage = "admission"
	rcloneFailureSavedVaultValidation      rcloneApplicationFailureStage = "saved_vault_validation"
	rcloneFailureNativeValidation          rcloneApplicationFailureStage = "native_validation"
	rcloneFailureProtectedRecordValidation rcloneApplicationFailureStage = "protected_record_validation"
	rcloneFailureConfigActivation          rcloneApplicationFailureStage = "config_activation"
	rcloneFailureArtifactWork              rcloneApplicationFailureStage = "artifact_work"
	rcloneFailureDatabaseCredentialUpdate  rcloneApplicationFailureStage = "database_credential_update"
)

func failRcloneApplication(outcome rcloneApplicationOutcome, stage rcloneApplicationFailureStage, err error) (rcloneApplicationOutcome, error) {
	outcome.FailureStage = stage
	return outcome, err
}

func assessedUsability(value bool) *bool { return &value }

func attachedUsableRcloneOutcome(outcome rcloneApplicationOutcome) rcloneApplicationOutcome {
	outcome.Attached = true
	outcome.Usable = assessedUsability(true)
	return outcome
}

func addRcloneOutcome(response map[string]any, outcome rcloneApplicationOutcome) {
	response["activation"] = outcome.Activation
	response["attached"] = outcome.Attached
	if outcome.Usable != nil {
		response["usable"] = *outcome.Usable
	}
	if outcome.FailureStage != "" {
		response["failureStage"] = outcome.FailureStage
	}
}

func writeRcloneAuthorizationError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func writeRcloneApplicationError(w http.ResponseWriter, status int, outcome rcloneApplicationOutcome, err error) {
	message := "native rclone configuration follow-up failed"
	switch outcome.Activation.Disposition {
	case engines.RcloneConfigRetained:
		message = "native rclone configuration was retained; activation or its prerequisite failed"
	case engines.RcloneConfigActivated:
		message = "native rclone configuration was activated, but a later attachment or follow-up step failed"
	case engines.RcloneConfigIndeterminate:
		message = "native rclone configuration activation is indeterminate; attachment and usability require review"
	}
	if err == nil {
		message = "native rclone configuration lifecycle failed without a classified cause"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		rcloneApplicationOutcome
		Error string `json:"error"`
	}{rcloneApplicationOutcome: outcome, Error: message})
}

var rcloneAuthConnectorSupported = engines.SupportsConnector

// openRcloneAuthorizationPage opens the cloud sign-in page in the default
// browser, the same way the running instance opens its own web interface.
var openRcloneAuthorizationPage = desktop.OpenURL

// newRcloneAuthStore returns a store that returns each sign-in link to the UI
// without opening a browser.
func newRcloneAuthStore() *rcloneAuthStore {
	return &rcloneAuthStore{
		sessions:      map[string]rcloneAuthEntry{},
		start:         engines.StartRcloneAuthorization,
		now:           time.Now,
		lifetime:      rcloneAuthSessionLifetime,
		retryInterval: time.Minute,
	}
}

// newDesktopRcloneAuthStore also opens each sign-in link in the default
// browser.
func newDesktopRcloneAuthStore() *rcloneAuthStore {
	store := newRcloneAuthStore()
	store.openPage = openRcloneAuthorizationPage
	return store
}

func newContainerRcloneAuthStore(relayPort int) *rcloneAuthStore {
	store := newRcloneAuthStore()
	store.relayFactory = func(authorizationURL string) (io.Closer, error) {
		return startRcloneAuthRelay(relayPort, authorizationURL)
	}
	return store
}

func (store *rcloneAuthStore) expiredIDsLocked() []string {
	now := store.now()
	var ids []string
	for id, entry := range store.sessions {
		if !entry.finalUse && !now.Before(entry.expiresAt) {
			ids = append(ids, id)
		}
	}
	return ids
}

func (store *rcloneAuthStore) purgeExpired() {
	store.mu.Lock()
	ids := store.expiredIDsLocked()
	store.mu.Unlock()
	for _, id := range ids {
		store.mu.Lock()
		entry, ok := store.sessions[id]
		if !ok || entry.finalUse || store.now().Before(entry.expiresAt) {
			store.mu.Unlock()
			continue
		}
		_ = store.discardLocked(id, entry)
	}
}

func (store *rcloneAuthStore) scheduleLocked() {
	if store.timer != nil {
		store.timer.Stop()
		store.timer = nil
	}
	if store.shutdown || len(store.sessions) == 0 {
		return
	}
	var next time.Time
	for _, entry := range store.sessions {
		if entry.finalUse {
			continue
		}
		if next.IsZero() || entry.expiresAt.Before(next) {
			next = entry.expiresAt
		}
	}
	if next.IsZero() {
		return
	}
	delay := next.Sub(store.now())
	if delay < 0 {
		delay = 0
	}
	store.timer = time.AfterFunc(delay, func() {
		store.mu.Lock()
		store.timer = nil
		store.mu.Unlock()
		store.purgeExpired()
		store.mu.Lock()
		store.scheduleLocked()
		store.mu.Unlock()
	})
}

// launchWorker runs one native transition (the start, or one answer) on its
// own goroutine, because rclone's browser step keeps running until the
// provider calls back. The returned channel receives the sign-in link if the
// transition reaches that step.
func (store *rcloneAuthStore) launchWorker(
	ctx context.Context, provider string,
	flow *engines.RcloneAuthorizationFlow,
	answer string, generation uint64,
) (<-chan string, *rcloneAuthWorker) {
	workerCtx, cancel := context.WithCancel(ctx)
	worker := &rcloneAuthWorker{cancel: cancel, done: make(chan struct{}), generation: generation}
	urlReady := make(chan string, 1)
	onURL := func(value string) {
		select {
		case urlReady <- value:
		default:
		}
	}
	go func() {
		var result *engines.RcloneAuthorizationFlow
		var err error
		if flow == nil {
			result, err = store.start(workerCtx, "", provider, onURL)
		} else {
			err = flow.Continue(workerCtx, answer, onURL)
			result = flow
		}
		worker.mu.Lock()
		worker.flow, worker.err = result, err
		worker.mu.Unlock()
		close(worker.done)
	}()
	return urlReady, worker
}

func (store *rcloneAuthStore) waitTransition(
	requestCtx context.Context,
	id, provider string,
	urlReady <-chan string,
	worker *rcloneAuthWorker,
) (rcloneAuthStatus, error) {
	select {
	case authorizationURL := <-urlReady:
		if store.beforeHandoff != nil {
			store.beforeHandoff("url")
		}
		store.mu.Lock()
		entry, live := store.sessions[id]
		if requestCtx.Err() != nil || store.shutdown || !live || entry.worker != worker ||
			entry.generation != worker.generation || worker.urlHandedOff ||
			!store.now().Before(entry.expiresAt) {
			store.mu.Unlock()
			return rcloneAuthStatus{}, errors.Join(
				fmt.Errorf("rclone authorization session is unavailable"), store.close(id),
			)
		}
		var relay io.Closer
		if store.relayFactory != nil {
			var relayErr error
			relay, relayErr = store.relayFactory(authorizationURL)
			if relayErr != nil || relay == nil {
				if relayErr == nil {
					relayErr = fmt.Errorf("relay factory returned no listener")
				}
				store.mu.Unlock()
				return rcloneAuthStatus{}, errors.Join(
					fmt.Errorf("start rclone authorization callback relay: %w", relayErr), store.close(id),
				)
			}
			relay = &rcloneAuthRelayHandle{closer: relay}
		}
		// Relay admission is serialized with delete, expiry, and shutdown.
		// Recheck cancellation and deadline after the listener is created. If
		// either won while the factory was running, publish the idempotent handle
		// into the entry before unlocking so concurrent cleanup must drain it.
		if requestCtx.Err() != nil || !store.now().Before(entry.expiresAt) {
			entry.relay = relay
			store.sessions[id] = entry
			var relayErr error
			if relay != nil {
				// Production relay shutdown is bounded. Keep the store lock until
				// this just-created listener is closed so delete/expiry cannot
				// report cleanup while it is still accepting callbacks.
				relayErr = relay.Close()
			}
			store.mu.Unlock()
			return rcloneAuthStatus{}, errors.Join(
				fmt.Errorf("rclone authorization session is unavailable"), relayErr, store.close(id),
			)
		}
		worker.urlHandedOff = true
		entry.relay = relay
		store.sessions[id] = entry
		store.mu.Unlock()
		if relay != nil {
			go store.closeRelayAfterWorker(id, worker, relay)
		}
		if store.openPage != nil {
			// The link is returned below whether or not this works, so a user
			// without a usable browser here (no default browser, or no
			// graphical session) can still open it themselves.
			if err := store.openPage(authorizationURL); err != nil {
				log.Printf("Replicaro could not open the browser for cloud sign-in; the sign-in link is shown in Replicaro instead: %v", err)
			}
		}
		return rcloneAuthStatus{
			SessionID: id, Provider: provider, Status: "waiting_browser",
			AuthorizationURL: authorizationURL,
		}, nil
	case <-worker.done:
		return store.claimOutcome(requestCtx, id, worker)
	case <-requestCtx.Done():
		return rcloneAuthStatus{}, errors.Join(requestCtx.Err(), store.close(id))
	}
}

// closeRelayAfterWorker makes callback admission follow native worker
// lifetime even when the browser never polls the completed result. The entry
// retains the idempotent handle so the claimant or session cleanup still owns
// and observes any close error.
func (store *rcloneAuthStore) closeRelayAfterWorker(id string, worker *rcloneAuthWorker, relay io.Closer) {
	<-worker.done
	store.mu.Lock()
	entry, live := store.sessions[id]
	owned := live && entry.worker == worker && entry.generation == worker.generation && entry.relay == relay
	store.mu.Unlock()
	if owned {
		_ = relay.Close()
	}
}

func (store *rcloneAuthStore) claimOutcome(
	requestCtx context.Context,
	id string,
	worker *rcloneAuthWorker,
) (rcloneAuthStatus, error) {
	flow, workerErr, complete := worker.result()
	if !complete {
		return rcloneAuthStatus{}, fmt.Errorf("rclone authorization transition is still running")
	}
	store.mu.Lock()
	entry, ok := store.sessions[id]
	if store.shutdown || !ok || entry.worker != worker || entry.generation != worker.generation ||
		!store.now().Before(entry.expiresAt) {
		store.mu.Unlock()
		return rcloneAuthStatus{}, fmt.Errorf("rclone authorization session is unavailable")
	}
	if requestCtx != nil && requestCtx.Err() != nil {
		requestErr := requestCtx.Err()
		return rcloneAuthStatus{}, errors.Join(requestErr, store.discardLocked(id, entry))
	}
	if workerErr != nil || flow == nil {
		return rcloneAuthStatus{}, errors.Join(
			rcloneAuthTransitionFailure(worker), rcloneAuthWorkerFailure(workerErr), store.discardLocked(id, entry),
		)
	}
	relay := entry.relay
	store.mu.Unlock()
	if relay != nil {
		if relayErr := relay.Close(); relayErr != nil {
			return rcloneAuthStatus{}, errors.Join(
				fmt.Errorf("close rclone authorization callback relay: %w", relayErr), store.close(id),
			)
		}
	}
	ready, question := flow.Status()
	if store.beforeHandoff != nil {
		store.beforeHandoff("outcome")
	}
	store.mu.Lock()
	current, live := store.sessions[id]
	valid := live && !store.shutdown && current.worker == worker && current.relay == relay &&
		current.generation == worker.generation && store.now().Before(current.expiresAt)
	if !valid {
		store.mu.Unlock()
		return rcloneAuthStatus{}, fmt.Errorf("rclone authorization session is unavailable")
	}
	if requestCtx != nil && requestCtx.Err() != nil {
		requestErr := requestCtx.Err()
		return rcloneAuthStatus{}, errors.Join(requestErr, store.discardLocked(id, current))
	}
	if !ready && question == nil {
		store.mu.Unlock()
		return rcloneAuthStatus{}, errors.Join(
			rcloneAuthTransitionFailure(worker),
			fmt.Errorf("native rclone authorization returned no next action"), store.close(id),
		)
	}
	current.flow = flow
	current.worker = nil
	current.relay = nil
	// rclone's part is done for now, so the session's 15 minutes now count
	// from here, as they do from every later use.
	current.expiresAt = store.now().Add(store.lifetime)
	store.sessions[id] = current
	store.scheduleLocked()
	store.mu.Unlock()
	return authStatus(id, current.provider, ready, question), nil
}

func (store *rcloneAuthStore) startFlow(
	ctx context.Context,
	provider string,
) (rcloneAuthStatus, error) {
	id := uuid.NewString()
	store.mu.Lock()
	// rclone's sign-in callback listens on one fixed loopback port, so only
	// one sign-in can wait at the browser step. A session still waiting there
	// after its link went out has usually lost its page (a reload, a closed
	// tab, or a second Replicaro tab), and while it holds the port every new
	// sign-in fails. The newest sign-in wins, so end those sessions first.
	for !store.shutdown {
		staleID, stale, found := "", rcloneAuthEntry{}, false
		for candidateID, candidate := range store.sessions {
			if candidate.worker == nil || !candidate.worker.urlHandedOff {
				continue
			}
			if _, _, done := candidate.worker.result(); !done {
				staleID, stale, found = candidateID, candidate, true
				break
			}
		}
		if !found {
			break
		}
		// A folder that can't be removed stays behind as a retry owner with no
		// worker, so it can't match again and doesn't block this sign-in.
		_ = store.discardLocked(staleID, stale)
		store.mu.Lock()
	}
	if store.shutdown {
		store.mu.Unlock()
		return rcloneAuthStatus{}, fmt.Errorf("rclone authorization is shutting down")
	}
	store.starting.Add(1)
	defer store.starting.Done()
	// The session context only carries cancellation. How long a session lives
	// is expiresAt, which the expiry timer enforces: 15 minutes from Connect
	// or from an answer while rclone works (its browser step included, as
	// nothing can refresh a session while its worker runs), and 15 minutes
	// from the last use once it's ready or asking a question. A deadline on
	// this context couldn't move with those refreshes, and would cancel a
	// later answer's rclone step after 15 minutes from Connect.
	sessionCtx, cancel := context.WithCancel(context.Background())
	urlReady, worker := store.launchWorker(sessionCtx, provider, nil, "", 1)
	store.sessions[id] = rcloneAuthEntry{
		provider: provider, expiresAt: store.now().Add(store.lifetime), sessionCtx: sessionCtx,
		cancel: cancel, worker: worker, generation: 1,
	}
	store.scheduleLocked()
	store.mu.Unlock()
	return store.waitTransition(ctx, id, provider, urlReady, worker)
}

func authStatus(
	id, provider string,
	ready bool,
	question *engines.RcloneAuthQuestion,
) rcloneAuthStatus {
	status := "question"
	if ready {
		status = "ready"
	}
	return rcloneAuthStatus{
		SessionID: id, Provider: provider, Status: status, Question: question,
	}
}

func (store *rcloneAuthStore) continueFlow(
	ctx context.Context,
	id, answer string,
) (rcloneAuthStatus, error) {
	store.purgeExpired()
	store.mu.Lock()
	entry, ok := store.sessions[id]
	if store.shutdown || !ok || entry.cleanupErr != nil || entry.finalUse ||
		!store.now().Before(entry.expiresAt) {
		store.mu.Unlock()
		return rcloneAuthStatus{}, fmt.Errorf("rclone authorization session is unavailable")
	}
	if entry.worker != nil {
		store.mu.Unlock()
		return rcloneAuthStatus{}, fmt.Errorf("rclone authorization transition is already running")
	}
	flow := entry.flow
	if flow == nil {
		store.mu.Unlock()
		return rcloneAuthStatus{}, fmt.Errorf("rclone authorization session is unavailable")
	}
	// An answer is a use, and it also bounds the rclone step it starts,
	// which can include another browser step.
	entry.expiresAt = store.now().Add(store.lifetime)
	entry.generation++
	urlReady, worker := store.launchWorker(entry.sessionCtx, entry.provider, flow, answer, entry.generation)
	entry.worker = worker
	store.sessions[id] = entry
	store.scheduleLocked()
	store.mu.Unlock()
	return store.waitTransition(ctx, id, entry.provider, urlReady, worker)
}

func (store *rcloneAuthStore) status(id string) (rcloneAuthStatus, error) {
	store.purgeExpired()
	store.mu.Lock()
	entry, ok := store.sessions[id]
	store.mu.Unlock()
	if !ok || entry.cleanupErr != nil || entry.finalUse {
		return rcloneAuthStatus{}, fmt.Errorf("rclone authorization session is absent or expired")
	}
	if entry.worker != nil {
		_, _, complete := entry.worker.result()
		if complete {
			return store.claimOutcome(nil, id, entry.worker)
		}
		store.mu.Lock()
		current, live := store.sessions[id]
		valid := live && current.worker == entry.worker && current.generation == entry.generation &&
			!store.shutdown && store.now().Before(current.expiresAt)
		store.mu.Unlock()
		if !valid {
			return rcloneAuthStatus{}, fmt.Errorf("rclone authorization session is absent or expired")
		}
		return rcloneAuthStatus{
			SessionID: id, Provider: entry.provider, Status: "waiting_browser",
		}, nil
	}
	flow := entry.flow
	if flow == nil {
		return rcloneAuthStatus{}, fmt.Errorf("rclone authorization session is absent or expired")
	}
	ready, question := flow.Status()
	if !ready && question == nil {
		return rcloneAuthStatus{}, errors.Join(
			fmt.Errorf("native rclone authorization returned no next action"), store.close(id),
		)
	}
	store.mu.Lock()
	current, live := store.sessions[id]
	valid := live && !store.shutdown && current.flow == flow && current.worker == nil &&
		current.generation == entry.generation && store.now().Before(current.expiresAt)
	store.mu.Unlock()
	if !valid {
		return rcloneAuthStatus{}, fmt.Errorf("rclone authorization session is absent or expired")
	}
	return authStatus(id, entry.provider, ready, question), nil
}

func (store *rcloneAuthStore) configPath(id, provider string) (string, error) {
	store.purgeExpired()
	store.mu.Lock()
	entry, ok := store.sessions[id]
	store.scheduleLocked()
	store.mu.Unlock()
	flow, complete := entry.flow, entry.worker == nil
	if !ok || !complete || flow == nil || flow.Provider() != provider {
		return "", fmt.Errorf("rclone authorization session does not match this provider")
	}
	if entry.cleanupErr != nil {
		return "", fmt.Errorf("rclone authorization session cleanup is pending: %w", entry.cleanupErr)
	}
	return flow.StagedConfigPath()
}

func (store *rcloneAuthStore) publishConfig(
	ctx context.Context,
	id, provider, repositoryID string,
) (engines.RcloneConfigActivation, error) {
	store.mu.Lock()
	entry, ok := store.sessions[id]
	store.mu.Unlock()
	flow, complete := entry.flow, entry.worker == nil
	if !ok || !complete || flow == nil || flow.Provider() != provider || !entry.finalUse {
		return engines.RcloneConfigActivation{Disposition: engines.RcloneConfigRetained}, fmt.Errorf("rclone authorization final-use ownership is unavailable")
	}
	return flow.PublishVaultConfig(ctx, repositoryID)
}

func (store *rcloneAuthStore) close(id string) error {
	store.mu.Lock()
	entry, ok := store.sessions[id]
	if !ok {
		store.scheduleLocked()
		store.mu.Unlock()
		return nil
	}
	if entry.finalUse {
		store.mu.Unlock()
		return fmt.Errorf("rclone authorization session is completing a vault transaction")
	}
	return store.discardLocked(id, entry)
}

// discardLocked takes id out of the store, so no request, timer or relay can
// use it any more, and then disposes of it. The caller holds store.mu;
// discardLocked releases it first, because disposing waits for the native
// worker to exit. closeAll waits for every discard still running.
func (store *rcloneAuthStore) discardLocked(id string, entry rcloneAuthEntry) error {
	delete(store.sessions, id)
	store.cleanups.Add(1)
	store.scheduleLocked()
	store.mu.Unlock()
	defer store.cleanups.Done()
	return store.dispose(id, entry)
}

// dispose ends a session that is no longer in the store: it closes the Docker
// callback relay, cancels the native worker and waits for it, and removes the
// session's private folders. When a folder can't be removed, the entry comes
// back under the same id as a retry owner that the expiry timer tries again
// after retryInterval, and that blocks any further use of the session. During
// shutdown nothing retries later, so it tries three times in all and keeps a
// failure that remains for closeAll to report.
func (store *rcloneAuthStore) dispose(id string, entry rcloneAuthEntry) error {
	var relayErr error
	if entry.relay != nil {
		relayErr = entry.relay.Close()
		entry.relay = nil
	}
	if entry.cancel != nil {
		entry.cancel()
	}
	if entry.worker != nil {
		entry.worker.cancel()
		<-entry.worker.done
		if flow, _, _ := entry.worker.result(); flow != nil {
			entry.flow = flow
		}
		entry.worker = nil
	}
	if entry.flow == nil {
		return relayErr
	}
	err := entry.flow.Close()
	if err == nil {
		return relayErr
	}
	store.mu.Lock()
	if !store.shutdown {
		if _, exists := store.sessions[id]; !exists {
			entry.cleanupErr = err
			entry.finalUse = false
			entry.expiresAt = store.now().Add(store.retryInterval)
			store.sessions[id] = entry
			store.scheduleLocked()
		}
		store.mu.Unlock()
		return errors.Join(relayErr, fmt.Errorf("clean up rclone authorization session: %w", err))
	}
	store.mu.Unlock()
	for attempt := 1; attempt < 3 && err != nil; attempt++ {
		err = entry.flow.Close()
	}
	if err == nil {
		return relayErr
	}
	wrapped := fmt.Errorf("clean up rclone authorization session %s: %w", id, err)
	store.mu.Lock()
	store.shutdownCleanupErrs = append(store.shutdownCleanupErrs, wrapped)
	store.mu.Unlock()
	return errors.Join(relayErr, wrapped)
}

// closeAll ends every session for shutdown. Shutdown can call it more than
// once (see the staged shutdown in main); each failure is reported by the
// first call that sees it, so a later call doesn't log it again.
func (store *rcloneAuthStore) closeAll() error {
	store.mu.Lock()
	store.shutdown = true
	if store.timer != nil {
		store.timer.Stop()
		store.timer = nil
	}
	entries := make(map[string]rcloneAuthEntry, len(store.sessions))
	for id, entry := range store.sessions {
		if entry.finalUse {
			continue
		}
		entries[id] = entry
		delete(store.sessions, id)
	}
	store.mu.Unlock()
	var errs []error
	// Closing relays and cancelling workers is a separate pass ahead of any
	// waiting: one slow reap must never leave a later callback or worker
	// admitted until its 15-minute deadline.
	stopAll := func() {
		for id, entry := range entries {
			if entry.relay != nil {
				if relayErr := entry.relay.Close(); relayErr != nil {
					errs = append(errs, relayErr)
				}
				entry.relay = nil
				entries[id] = entry
			}
			if entry.cancel != nil {
				entry.cancel()
			}
			if entry.worker != nil {
				entry.worker.cancel()
			}
		}
	}
	stopAll()
	store.starting.Wait()
	store.finalUses.Wait()
	store.mu.Lock()
	for id, entry := range store.sessions {
		entries[id] = entry
		delete(store.sessions, id)
	}
	store.mu.Unlock()
	stopAll()
	for id, entry := range entries {
		// A failure is kept in shutdownCleanupErrs and reported below.
		_ = store.dispose(id, entry)
	}
	store.cleanups.Wait()
	store.mu.Lock()
	errs = append(errs, store.shutdownCleanupErrs...)
	store.shutdownCleanupErrs = nil
	store.mu.Unlock()
	return errors.Join(errs...)
}

func mergeRcloneAuthorizedOptions(
	submitted, native map[string]string,
) (map[string]string, error) {
	result := make(map[string]string, len(native)+2)
	for key, value := range submitted {
		if strings.HasPrefix(key, "rclone_") {
			result[key] = value
			continue
		}
		if strings.TrimSpace(value) != "" {
			return nil, fmt.Errorf("native rclone login fields cannot be supplied through the API")
		}
	}
	for key, value := range native {
		result[key] = value
	}
	return result, nil
}

// mergeOptionsForFinalTransaction exclusively leases a completed native
// authorization while a create/connect transaction is in flight. Only a
// retained publication releases the lease for retry. Activated and
// indeterminate publication consume the session before cleanup, and a later
// error never restores usability. The existing-vault Check takes the same
// lease and always releases it as retained: it reads the staged rclone.conf
// too, and expiry skips a leased session, so that config can't be removed
// while the Check runs. Taking the lease and releasing it as retained are
// both uses that restart the session's 15 minutes.
func (store *rcloneAuthStore) mergeOptionsForFinalTransaction(
	sessionID, provider string,
	submitted map[string]string,
) (map[string]string, func(engines.RcloneConfigDisposition) error, error) {
	if !engines.IsRcloneNativeLoginProvider(provider) {
		noFinish := func(engines.RcloneConfigDisposition) error { return nil }
		if strings.TrimSpace(sessionID) != "" {
			return nil, noFinish, fmt.Errorf("rclone authorization session is invalid for this storage type")
		}
		options := make(map[string]string, len(submitted))
		for key, value := range submitted {
			options[key] = value
		}
		return options, noFinish, nil
	}
	if strings.TrimSpace(sessionID) == "" {
		return nil, nil, fmt.Errorf(
			"connect the %s account with rclone before continuing", provider,
		)
	}

	store.purgeExpired()
	store.mu.Lock()
	entry, ok := store.sessions[sessionID]
	flow, complete := entry.flow, entry.worker == nil
	switch {
	case store.shutdown:
		store.scheduleLocked()
		store.mu.Unlock()
		return nil, nil, fmt.Errorf("rclone authorization is shutting down")
	case !ok || !complete || flow == nil || flow.Provider() != provider ||
		!store.now().Before(entry.expiresAt):
		store.scheduleLocked()
		store.mu.Unlock()
		return nil, nil, fmt.Errorf("rclone authorization session does not match this provider")
	case entry.cleanupErr != nil:
		store.scheduleLocked()
		store.mu.Unlock()
		return nil, nil, fmt.Errorf(
			"rclone authorization session cleanup is pending: %w", entry.cleanupErr,
		)
	case entry.finalUse:
		store.scheduleLocked()
		store.mu.Unlock()
		return nil, nil, fmt.Errorf("rclone authorization session is already completing a vault transaction")
	}
	entry.flow = flow
	entry.finalUse = true
	entry.expiresAt = store.now().Add(store.lifetime)
	store.sessions[sessionID] = entry
	store.finalUses.Add(1)
	store.scheduleLocked()
	store.mu.Unlock()

	var once sync.Once
	var finishErr error
	finish := func(disposition engines.RcloneConfigDisposition) error {
		once.Do(func() {
			defer store.finalUses.Done()
			store.mu.Lock()
			current, exists := store.sessions[sessionID]
			if !exists || !current.finalUse {
				finishErr = fmt.Errorf("rclone authorization final-use ownership was lost")
				store.scheduleLocked()
				store.mu.Unlock()
				return
			}
			if disposition == engines.RcloneConfigRetained {
				current.finalUse = false
				current.expiresAt = store.now().Add(store.lifetime)
				store.sessions[sessionID] = current
				store.scheduleLocked()
				store.mu.Unlock()
				return
			}
			// Activated and indeterminate both consume the sign-in, so it
			// leaves the store before its folders are removed and can't be
			// applied again even if that removal fails.
			delete(store.sessions, sessionID)
			store.scheduleLocked()
			store.mu.Unlock()
			finishErr = store.dispose(sessionID, current)
		})
		return finishErr
	}

	native, err := entry.flow.IdentityOptions()
	if err != nil {
		_ = finish(engines.RcloneConfigRetained)
		return nil, nil, err
	}
	result, err := mergeRcloneAuthorizedOptions(submitted, native)
	if err != nil {
		_ = finish(engines.RcloneConfigRetained)
		return nil, nil, err
	}
	return result, finish, nil
}

func registerRcloneAuthHandlers(
	mux *http.ServeMux,
	db *sql.DB,
	store *rcloneAuthStore,
) {
	handle(mux, "/api/rclone/auth/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Provider string `json:"provider"`
		}
		if err := decodeRequest(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !rcloneAuthConnectorSupported(engines.ResticID, req.Provider) {
			badRequest(w, "this Restic rclone connector is unavailable for the current target")
			return
		}
		status, err := store.startFlow(r.Context(), req.Provider)
		if err != nil {
			writeRcloneAuthorizationError(w, http.StatusBadRequest,
				"native rclone authorization could not be started")
			return
		}
		if status.AuthorizationURL != "" {
			w.Header().Set("Cache-Control", "no-store")
		}
		writeJSON(w, status)
	})
	handle(mux, "/api/rclone/auth/continue", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			SessionID string `json:"sessionId"`
			Answer    string `json:"answer"`
		}
		if err := decodeRequest(r, &req); err != nil ||
			strings.TrimSpace(req.SessionID) == "" {
			badRequest(w, "sessionId and answer are required")
			return
		}
		status, err := store.continueFlow(r.Context(), req.SessionID, req.Answer)
		if err != nil {
			writeRcloneAuthorizationError(w, http.StatusBadRequest,
				"native rclone authorization could not be continued")
			return
		}
		if status.AuthorizationURL != "" {
			w.Header().Set("Cache-Control", "no-store")
		}
		writeJSON(w, status)
	})
	handle(mux, "/api/rclone/auth/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			SessionID string `json:"sessionId"`
		}
		if err := decodeRequest(r, &req); err != nil || strings.TrimSpace(req.SessionID) == "" {
			badRequest(w, "sessionId is required")
			return
		}
		status, err := store.status(req.SessionID)
		if err != nil {
			// A sign-in that failed is reported as a failure, once, as it ends.
			// Unknown, cancelled and expired sessions stay 404.
			for _, failure := range []error{errRcloneAuthStartFailed, errRcloneAuthContinueFailed} {
				if errors.Is(err, failure) {
					writeRcloneAuthorizationError(w, http.StatusBadRequest, failure.Error())
					return
				}
			}
			writeRcloneAuthorizationError(w, http.StatusNotFound,
				"native rclone authorization session is unavailable")
			return
		}
		status.AuthorizationURL = ""
		writeJSON(w, status)
	})
	handle(mux, "/api/rclone/auth/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := store.close(strings.TrimSpace(r.URL.Query().Get("id"))); err != nil {
			writeRcloneAuthorizationError(w, http.StatusInternalServerError,
				"temporary native authorization cleanup failed; retry cleanup")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handle(mux, "/api/rclone/auth/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			SessionID    string `json:"sessionId"`
			RepositoryID string `json:"repositoryId"`
		}
		if err := decodeRequest(r, &req); err != nil ||
			strings.TrimSpace(req.SessionID) == "" ||
			strings.TrimSpace(req.RepositoryID) == "" {
			badRequest(w, "sessionId and repositoryId are required")
			return
		}
		repo, err := database.GetRepository(db, req.RepositoryID)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		if repo.Engine != engines.ResticID ||
			!engines.IsRcloneNativeLoginProvider(repo.Connector) {
			badRequest(w, "this vault does not use native rclone login")
			return
		}
		options, finish, err := store.mergeOptionsForFinalTransaction(
			req.SessionID, repo.Connector, nil,
		)
		if err != nil {
			writeRcloneAuthorizationError(w, http.StatusBadRequest,
				"native rclone authorization session is unavailable or not ready")
			return
		}
		stagedConfig, err := store.configPath(req.SessionID, repo.Connector)
		if err != nil {
			_ = finish(engines.RcloneConfigRetained)
			writeRcloneAuthorizationError(w, http.StatusBadRequest,
				"native rclone authorization session configuration is unavailable")
			return
		}
		outcome, applyErr := applyRcloneAuthorizedCredentials(
			r.Context(), db, repo, options, stagedConfig,
			func() (engines.RcloneConfigActivation, error) {
				return store.publishConfig(
					r.Context(), req.SessionID, repo.Connector, repo.ID,
				)
			},
		)
		finishErr := finish(outcome.Activation.Disposition)
		if applyErr != nil {
			status := http.StatusBadRequest
			if errors.Is(applyErr, database.ErrRepositoryConnectionReserved) ||
				errors.Is(applyErr, database.ErrVaultPasswordChangeRecoveryRequired) {
				status = http.StatusConflict
			}
			writeRcloneApplicationError(w, status, outcome, errors.Join(applyErr, finishErr))
			return
		}
		if finishErr != nil {
			// The login is saved and in use; only the temporary session is
			// left. That is completed with issues, not an error the page would
			// read as "sign-in failed".
			outcome.addIssue("The rclone login was saved, but its temporary authorization session still needs cleanup.")
		}
		writeJSON(w, outcome)
	})
}

func applyRcloneAuthorizedCredentials(
	ctx context.Context,
	db *sql.DB,
	repo models.Repository,
	providerOptions map[string]string,
	stagedConfig string,
	publishConfig func() (engines.RcloneConfigActivation, error),
) (rcloneApplicationOutcome, error) {
	outcome := rcloneApplicationOutcome{
		Activation: engines.RcloneConfigActivation{Disposition: engines.RcloneConfigRetained},
		Attached:   true,
	}
	// A native-login apply runs in the foreground while the user waits. OneDrive
	// and Google Drive in particular can still be publishing the protected
	// profile, holding this vault's lock, when the browser flow returns. Wait for
	// that in-process lock holder instead of trying once (a single try makes
	// slower providers report a spurious busy error), then revalidate every check
	// and saved-vault precondition below while holding the lock. Cancelling the
	// wait still leaves the retained authorization retryable. The wait does not
	// unlock any native work and does not cover races with other computers.
	unlock, lockErr := vaultlock.AcquireExclusiveContext(ctx, repo.ID)
	if lockErr != nil {
		return failRcloneApplication(outcome, rcloneFailureAdmission, lockErr)
	}
	defer unlock()
	// Authorization may outlive the saved-row review. A pending reconnect or
	// password change must be rejected under the vault lock before native
	// validation, artifact staging, or canonical rclone config publication, not
	// only by the database reservation check at commit.
	if err := database.ValidateRepositoryMutationAdmission(db, repo.ID); err != nil {
		// The handler loaded repo before waiting for the vault lock, and a removal
		// may have committed while we waited. Only a confirmed "row not found" under
		// the lock marks the vault as no longer attached; any other error keeps the
		// attachment state loaded before the wait.
		if errors.Is(err, sql.ErrNoRows) {
			outcome.Attached = false
		}
		return failRcloneApplication(outcome, rcloneFailureAdmission, err)
	}
	current, err := database.GetRepository(db, repo.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			outcome.Attached = false
		}
		return failRcloneApplication(outcome, rcloneFailureSavedVaultValidation, err)
	}
	if current.Engine != repo.Engine || current.Connector != repo.Connector {
		return failRcloneApplication(outcome, rcloneFailureSavedVaultValidation, fmt.Errorf("vault changed during rclone authorization"))
	}
	repo = current
	integration, ok := integrations.Find(repo.Connector)
	if !ok {
		return failRcloneApplication(outcome, rcloneFailureSavedVaultValidation, fmt.Errorf("rclone provider definition is unavailable"))
	}
	merged := make(map[string]string, len(providerOptions)+2)
	for key, value := range providerOptions {
		merged[key] = value
	}
	normalized, err := engines.NormalizeConnectorOptions(repo.Engine, integration, merged)
	if err != nil {
		return failRcloneApplication(outcome, rcloneFailureSavedVaultValidation, err)
	}
	oldIdentity, oldErr := vaultidentity.PhysicalIdentityWithOptions(
		repo.Connector, repo.Location, repo.ConnectorOptions,
	)
	newIdentity, newErr := vaultidentity.PhysicalIdentityWithOptions(
		repo.Connector, repo.Location, normalized,
	)
	if oldErr != nil || newErr != nil || oldIdentity != newIdentity {
		return failRcloneApplication(outcome, rcloneFailureSavedVaultValidation, fmt.Errorf("rclone login addresses a different physical vault"))
	}
	candidate := repo
	candidate.ConnectorOptions = normalized
	candidate.RcloneConfigPath = stagedConfig
	// This uses the staged rclone credentials for the existing native access
	// probe. The protected root/profile checks below match the saved vault
	// records, and backup admission compares the actual native ID before backup.
	// Do not add another Restic config read here for the false-success case
	// described at validateRotatedCredentials: it adds a remote round trip, and
	// backup admission already checks the repository ID.
	if err := validateRotatedCredentials(ctx, candidate); err != nil {
		return failRcloneApplication(outcome, rcloneFailureNativeValidation, fmt.Errorf("rclone login could not access the native vault"))
	}
	rootData, err := readRootWithRotatedCredentials(ctx, candidate)
	if err != nil {
		return failRcloneApplication(outcome, rcloneFailureProtectedRecordValidation, fmt.Errorf("rclone login could not access the vault root"))
	}
	root, err := vaultprofile.ParseRoot(rootData, repo.Connector)
	if err != nil {
		return failRcloneApplication(outcome, rcloneFailureProtectedRecordValidation, fmt.Errorf("rclone login returned an invalid vault root"))
	}
	if !root.Identifies(repo) {
		return failRcloneApplication(outcome, rcloneFailureProtectedRecordValidation, fmt.Errorf("rclone login addresses a different vault"))
	}
	profileData, err := readProfileWithRotatedCredentials(ctx, candidate)
	if err != nil {
		return failRcloneApplication(outcome, rcloneFailureProtectedRecordValidation, fmt.Errorf("rclone login could not access the recovery profile"))
	}
	profile, err := vaultprofile.Parse(profileData)
	if err != nil {
		return failRcloneApplication(outcome, rcloneFailureProtectedRecordValidation, fmt.Errorf("rclone login returned an invalid recovery profile"))
	}
	if profile.VaultUUID != repo.ID || profile.ProfileUUID != repo.ProfileUUID ||
		profile.Attachment.ClientUUID != repo.ClientUUID || profile.Attachment.Generation != repo.AttachmentGeneration {
		return failRcloneApplication(outcome, rcloneFailureProtectedRecordValidation, fmt.Errorf("rclone login addresses a different vault"))
	}
	if publishConfig == nil {
		return failRcloneApplication(outcome, rcloneFailureConfigActivation, fmt.Errorf("rclone vault config publication is unavailable"))
	}
	activation, publishErr := publishConfig()
	outcome.Activation = activation
	if publishErr != nil {
		return failRcloneApplication(outcome, rcloneFailureConfigActivation, fmt.Errorf("rclone login could not activate the native vault config"))
	}
	stage, err := stageRepositoryArtifacts(
		repo, engines.RepositoryArtifactCredentialRotation,
	)
	if err != nil {
		return failRcloneApplication(outcome, rcloneFailureArtifactWork, fmt.Errorf("stale local engine credentials could not be staged: %w", err))
	}
	if err := updateRepositoryCredentials(db, repo.ID, normalized); err != nil {
		if restoreErr := restoreRepositoryArtifacts(stage); restoreErr != nil {
			return failRcloneApplication(outcome, rcloneFailureDatabaseCredentialUpdate, fmt.Errorf("credential update failed and old local engine artifacts could not be restored: %v; restore error: %w", err, restoreErr))
		}
		return failRcloneApplication(outcome, rcloneFailureDatabaseCredentialUpdate, err)
	}
	outcome.Attached = true
	outcome.Usable = assessedUsability(true)
	// The new login is committed above. A quarantined old engine artifact
	// that cannot be removed is left for manual cleanup and makes the apply
	// completed with issues; it is not a failure, because nothing should be
	// retried.
	//
	// The issue text is fixed on purpose. The finalize error names the local
	// app-data quarantine path, and apply responses never carry sensitive
	// paths (before this was completed with issues, the same case went out
	// through writeRcloneApplicationError, which also sends a fixed message).
	// The raw error goes to the local log for whoever does the cleanup.
	if err := finalizeRepositoryArtifacts(stage); err != nil {
		log.Printf("cloud sign-in apply for vault %s: quarantined old engine artifacts could not be removed: %v", repo.ID, err)
		outcome.addIssue("credentials were updated but quarantined old engine artifacts require manual cleanup")
	}
	_ = database.LogActivity(db, "Repository rclone account reconnected: "+repo.Name)
	return outcome, nil
}

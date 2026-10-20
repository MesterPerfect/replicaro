import type { BackupJob } from "../types";
import { jobSourceTooltip } from "../jobSourceDisplay";
import { FloatingTooltip } from "./FloatingTooltip";

// See jobSourceDisplay.ts for why managed snapshots are labelled by job. The
// job name stays the accessible name; the "Job source:" text is the tooltip's
// description.
//
// Don't use the shared Tooltip here: File History's results list clips a
// popup rendered inside the row.
export function JobSourceLabel({ job, className = "" }: { job: BackupJob; className?: string }) {
	return (
		<FloatingTooltip content={jobSourceTooltip(job)} label={job.name} className={`job-source-label ${className}`.trim()}>
			<span className="job-source-name">{job.name}</span>
		</FloatingTooltip>
	);
}

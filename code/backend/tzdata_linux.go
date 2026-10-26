//go:build linux

package main

// Go's own copy of the IANA time zone database, built into the Linux binary.
// Go reads it only when the system has no zone data of its own, so desktop
// Linux and the Docker image, which has Alpine's tzdata in
// /usr/share/zoneinfo, both use the system database, the same one the
// engines, hooks and the image's own tools use. It stays for Linux hosts
// without zone files, where a TZ such as Europe/Berlin would otherwise
// silently fall back to UTC, and backup job schedules and monthly vault check
// and maintenance would follow UTC. It adds about 450 KB.
//
// Keep this an import rather than the timetzdata build tag, so tests and
// development builds load zones the same way release builds do.
import _ "time/tzdata"

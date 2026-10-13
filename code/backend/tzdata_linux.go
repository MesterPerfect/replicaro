//go:build linux

package main

// Go's own copy of the IANA time zone database, built into the Linux binary.
// The Docker image has no /usr/share/zoneinfo, so without it a container
// started with -e TZ=Europe/Berlin silently runs in UTC, and cron schedules
// and the daily/weekly/monthly vault check and maintenance times follow UTC.
// Go reads this copy only when the system has no zone data of its own, so
// desktop Linux keeps using the system database. It adds about 450 KB.
//
// Keep this an import rather than the timetzdata build tag, so tests and
// development builds load zones the same way release builds do.
import _ "time/tzdata"

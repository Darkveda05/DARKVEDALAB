# sharelab — default Samba file share

This folder is bind-mounted to `/DATA/sharelab` inside the portal container
and shared as `\\HOST\sharelab` (user `admin`, read & write).

* Put files here and they appear in the share immediately.
* The portal manages access per user (Samba **Add User** / share access matrix).
* Files in this folder are **yours, not the repo's** — everything except this
  README is git-ignored, so dropping files here never pollutes a commit.

# Pixora Today

One private glance at every Pixora app: Spend Log, Split Log and Contour.
Live at https://spoolsync.github.io/pixora/

## What it shows
- **Needs attention:** bills due soon, return deadlines, what you owe friends, food or
  purchases not logged yet today, today's workout.
- **One card per app:** this month's spending and bills, your split balances, today's
  calories, protein, workouts and weight trend.
- Updates live while open, and works offline with the last copy.

## How it stays private
- The dashboard makes an encryption key pair. The public half sits in your own account
  (`apps/dashboard/users/<uid>`); the private half is kept there only wrapped by your
  dashboard passcode, and on each phone in a form web pages can't read out.
- Each app encrypts a short summary to that public key on the phone and stores it in
  `apps/dashboard/users/<uid>/inbox/<app>`. The server, the project owner and any AI see
  only ciphertext. Other accounts are refused by the database rules.
- Nothing is sent when you're not signed in or haven't set up the dashboard.
- The Pixora passcode is exactly 4 digits and the same in every app. Settings > Pixora passcode
  changes it for every app; the master key stays the same, so no data is re-encrypted.
  Accounts with an older passcode are asked once to pick 4 digits (`pixora-pin.js`).
- Once you unlock one Pixora app in a browser, the others in that browser open without asking
  (a non-extractable key in this site's storage). Each home-screen app on iPhone has its own
  storage, so each asks once per phone, then never again.
- Forgot the passcode? Settings > Start over makes new keys; each app sends a fresh summary
  the next time you open it. Nothing inside the apps is touched.

## For app builders
`pixora-summary.js` is the shared module. Each app includes a copy and calls
`PixoraSummary.schedule("<app>", getArgs)` whenever its data changes. Keep the copies in
sync across repos.

## Cloud
Pixora Firebase project `pixora-bca1f`, web app "Pixora Today". The generic
`apps/{app}/users/{uid}` owner-only rule covers the dashboard; no extra rules needed.

When you change files, bump `CACHE` in `sw.js` so installed phones pick up the new copy.

## Pixora Admin
https://spoolsync.github.io/pixora/admin/ shows anonymous feature counts and error reports for
every app: no account ids, amounts, names or anything a person typed. Only the verified admin
email in `firestore.rules` (`isPixoraAdmin`) can read them. Each app counts through
`pixora-usage.js` (shared copy in every app).

## Database rules: one source of truth
`firestore.rules` here is the complete, live rule set for the whole Pixora project. Edit this
file, then paste the whole file into Firebase console > Firestore > Rules and Publish. Never
paste only one app's section: that replaces every other app's rules.

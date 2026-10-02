"""Legal and accessibility text for the OMIVIA footer. Draft wording: have a lawyer review before real launch."""
CONTACT = "omivia.cyber@gmail.com" 
UPDATED = "2 October 2026"
MIN_AGE = 18

TERMS = f"""# Terms of Service
*Last updated {UPDATED}*

**1. What OMIVIA is.** OMIVIA is a prototype security dashboard that detects brute force and password spray attacks from authentication logs. It is provided as is, without warranty.

**2. Who can use it.** You must be {MIN_AGE} or older. We ask for your date of birth once at sign-up to check this and do not keep it.

**3. Your account.** Keep your password private. You are responsible for activity under your account. You can delete your account at any time in Settings.

**4. Your data.** You keep ownership of the logs you upload. You confirm you have the right to analyze them and that doing so does not breach your employer's policies or the law. Our use of your data is described in the Privacy Policy.

**5. Acceptable use.** Do not use OMIVIA to attack, probe or gain access to systems you don't own or have permission to test, to upload malware, or to disrupt the service.

**6. Detections can be wrong.** Alerts and severity ratings are decision support, not proof. Review evidence before locking accounts or acting on a result.

**7. Liability.** To the extent the law allows, we are not liable for indirect or consequential losses, or for actions taken on the basis of a detection.

**8. Changes and ending.** We may update these terms or suspend accounts that break them. If the terms change materially we will ask you to accept them again.

**9. Contact.** {CONTACT}
"""

PRIVACY = f"""# Privacy Policy
*Last updated {UPDATED}*

## What we record
- **Account:** your email, display name, a salted hash of your password (never the password itself), the date you registered, the terms version you accepted, a flag confirming you are {MIN_AGE}+, and your AI training choice.
- **Uploaded logs:** the CSV files you upload while signed in, stored exactly as you provided them (typically timestamps, usernames, login results, endpoints and client fingerprints, plus any other columns in your file).
- **Session data:** held in server memory while you use the app and discarded when the session ends.

## What we do not record
- Your date of birth, your plain-text password, advertising or analytics identifiers.
- IP addresses. OMIVIA does not collect or store them, and its detections do not use them. The server or hosting service running OMIVIA may keep standard technical logs, which can include IP addresses, outside the app's control.
- Anything from guest sessions. Guest uploads are processed in memory and never saved.

## Where we use your data
- To sign you in and run your dashboard (detections, incidents, targeted accounts, investigation).
- To let you reopen the log files you saved.
- **To train AI.** Unless you opt out, the log files you upload may be used to train, tune and evaluate OMIVIA's detection models, the AI that classifies login activity as brute force or password spray. Only uploaded log files are eligible. Your email, name and password are never part of training data.

## Your AI training choice
You choose at sign-up and can change it any time in **Settings, Privacy**. When you switch it off, your files are excluded from all future training runs immediately. Models already trained in a completed run cannot have your data removed from them. Guests are never included.

## Sharing
We do not sell your data. In this prototype it stays on the server running OMIVIA and is not shared with other companies. The one exception is the page font: your browser loads IBM Plex Sans from Google Fonts, so Google receives your IP address and browser details when a page loads.

## Keeping and deleting data
We keep your account and files until you delete them. **Settings, Delete account** immediately erases your login record, password hash, preferences and every stored file. You can also delete only your uploaded files. The app makes no backups of its own.

## Your rights
You can ask to see, correct, export or delete your data, or withdraw consent for AI training, by using Settings or contacting {CONTACT}.

## Age
OMIVIA is for people aged {MIN_AGE} and over.

## Changes and contact
We will update this page when our practices change. Questions: {CONTACT}
"""

A11Y = f"""# Accessibility Statement
*Last updated {UPDATED}*

OMIVIA aims to be usable by everyone, including people who use screen readers, keyboards, magnification or high contrast settings. We are working toward conformance with **WCAG 2.2 level AA**.

## What we have done
- **Light and dark themes** (Settings, Appearance) with text and controls chosen to meet AA contrast ratios.
- **Severity never relies on colour alone.** Every rating also shows a text label (Critical, High).
- **Real data tables** with column headers, which scroll horizontally and can be reached with the keyboard.
- **Charts have table equivalents.** The same incidents and events appear in the tables on each page.
- **Visible keyboard focus** on buttons, inputs and links.
- **Plain language** for errors, with a clear way back from the error page.

## Known limitations
- Charts are visual. Hover details are not announced by every screen reader, so use the tables for the same figures.
- OMIVIA is built on Streamlit. Some built-in components, such as dropdown menus and file pickers, may have gaps we can't fully control.
- Toast notifications disappear after a few seconds. Critical incidents are always listed in the Incidents page.
- This statement is based on our own review. It has not yet been independently audited.

## Feedback
If something is hard to use, tell us at {CONTACT}. Please include the page and the assistive technology you use. We aim to reply within 5 working days.
"""

DOCS = {"terms": TERMS, "privacy": PRIVACY, "a11y": A11Y}
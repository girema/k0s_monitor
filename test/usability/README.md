# Usability round

The plan asks for usability tests with non-experts after M1 and M3 ([plan, section 16](../../docs/PLAN.md#16-testing-strategy)). In each session one person from the target audience works through eight real tasks in Basic mode, while a facilitator watches and takes notes. The texts and flows are then revised where people got stuck.

This folder has what a session needs:

- [`clusters/`](clusters/): three made-up clusters, served by the demo build in place of real ones:
  - **shop-prod**, the web shop: its web app crashes since an update, and its database storage fills up.
  - **shop-staging**: a server stopped, and an app that ran only there is down.
  - **office**: everything works.
- [`tasks.md`](tasks.md): the task cards to print, one per page, for the participant.
- [`notes.md`](notes.md): the facilitator's sheet for one session, with the questionnaires.

`go test ./internal/rules -run TestUsabilityClusters` checks that the clusters still show what the tasks expect.

## Who takes part

Recruit 3 to 5 people who would use k0s-monitor without knowing Kubernetes: support staff, operators, a customer's IT administrator. Five people find most of the problems; three are enough for a first round.

- People who work with Kubernetes every day aren't the target audience. If one takes part, note it, and count their results separately.
- People who built or tested k0s-monitor shouldn't take part.

Each session takes about 45 minutes, with one participant at a time.

## Before each session

1. On a Linux machine with Go (the jump host will do), in this repository, start the demo:

   ```sh
   make usability
   ```

   It builds `bin/k0s-monitor-demo` and serves the three clusters on `https://127.0.0.1:8443`, without sign-in. Every start begins with a new, empty database, so stop it (Ctrl+C) and start it again for each participant: problems marked "I'm on it" by the previous participant are gone. Start it just before the session, because the clusters' clock starts when the demo starts (their dates read 27 September 2026).

2. On the Windows PC the participant will use, connect to that machine and forward the port. Windows 10 has an SSH client built in; in PowerShell:

   ```powershell
   ssh -L 8443:127.0.0.1:8443 you@jump-host
   ```

   Leave that window open. Skip this step when the browser runs on the machine that runs the demo.

3. Open `https://127.0.0.1:8443/?mode=basic` in Edge or Chrome. The certificate is made up by the demo, so the browser warns about it: choose **Advanced**, then **Continue to 127.0.0.1**. Do this before the participant arrives.

4. Check the start page: it lists **office** (working), **shop-prod** and **shop-staging** (both need attention), and the switch at the top right shows **Basic**. shop-prod must show the storage problem ("will be full in about 4 hours"): it appears about ten seconds after the start, when the demo first reads the usage numbers.

5. Have ready: the printed task cards, a copy of [`notes.md`](notes.md), and a clock. Close other windows, and turn off notifications.

The blue banner about sign-in comes from the demo setup: if the participant asks, say it doesn't matter today.

## The session

| Part | Time |
|---|---|
| Welcome and consent | 3 min |
| Background questions | 3 min |
| Eight tasks, each followed by one question | 25–30 min |
| Questionnaire (SUS) and closing questions | 7 min |
| Thanks | 2 min |

### Welcome (read aloud)

> Thank you for helping. We're building a tool that tells people what's wrong with the systems that run their apps, and what to do about it. Today we're testing the tool, not you: if something is hard, that's the tool's fault, and exactly what we need to find.
>
> I'll give you some tasks, one at a time. Please think aloud while you work: say what you're looking for, what you expect, and what surprises you. I'll mostly stay quiet, because I want to see how the tool works without me. You can stop at any time.
>
> The systems you see aren't real, so nothing you do can break anything. The tool also never changes anything by itself.
>
> May I take notes? (If recording: may I record the screen and our voices? Only the team will see it.)

### Background questions

1. What is your job, and how do you deal with servers or apps in it?
2. Have you worked with Kubernetes, or heard of it? (never / heard of it / used it a little / use it regularly)
3. When something goes wrong with a system at work, what do you usually do first?

### Running the tasks

- Hand over one card at a time, and read it aloud. Start the clock when they start.
- **Don't help, and don't explain words.** If they ask, answer with a question: "What would you do if I weren't here?"
- Give a hint only when they are stuck for about two minutes, or ask for help twice. Then the task counts as *assisted*: note the hint. If a hint doesn't help, move on: the task counts as *failed*.
- A task ends when they give an answer, or say they would give up.
- After each task ask the one question on the notes sheet (how easy it was, 1 to 7), and ask what made it hard if the answer is 4 or less.
- Note their exact words when they are confused, surprised or wrong: these quotes are the most useful part.

Tasks build on each other: keep their order.

## The tasks and what counts as success

The participant reads the text in italics, from [`tasks.md`](tasks.md). Start each task on the page given; between tasks, go back to it if they are elsewhere.

**T1. Are all systems OK?** Start: the start page (All clusters).
*Your manager asks: "Are all our systems working right now? If not, which one should we look at first?"*
- Success: office works; shop-prod and shop-staging need attention. They pick one of the two because it has something marked "Fix now", or name both.
- Watch for: whether they read the cluster cards, open a cluster, or look at the colored marks in the menu.

**T2. What's wrong with the web shop?** Start: the start page.
*Customers say the web shop (shop-prod) has been showing errors for a while. Find out what is wrong with it.*
- Success: they find "The app web keeps crashing" and say why: a setting it needs (DATABASE_URL) is missing since an update.
- Partial (count as assisted): they find the crash, but not why.
- Watch for: whether the storage problem above it distracts them, and whether they open "How to fix".

**T3. What to do about it.** Start: where T2 ended.
*What should be done to get the web shop working again? Is it safe to do?*
- Success: undo the update (step 1); it is safe and the update can be made again later; whoever installs the app (with Helm or Argo CD) should undo it there, and add the missing setting.
- Watch for: whether they think k0s-monitor will fix it for them (it only shows what to do); whether they would copy the command themselves or send it on; whether they open "More checks for whoever manages the cluster", and what they make of it.

**T4. Will something run out?** Start: the shop-prod overview.
*Is anything in shop-prod about to run out? How much time is left?*
- Success: the database storage (postgres) will be full in about 4 hours, and that should be fixed now.
- Watch for: whether they connect "storage of postgres" with the shop's database.

**T5. Tell your colleagues you're on it.** Start: the shop-prod problems page.
*You'll handle the web crash yourself. Let your colleagues know, so that nobody else starts on it too.*
- Success: they open the crash and press "I'm on it".
- Then ask: *Where is the crash now? How would you find it again?* Success: they understand it was set aside, and find it with "Show 1 set aside" on the Problems page.

**T6. A problem in staging.** Start: the start page.
*A colleague says something is wrong in shop-staging. What is wrong, and who should do something about it?*
- Success: the server worker-3 stopped responding, and the app checkout is down because of it; someone who can reach that server (or whoever manages the servers) should check that it is on, connected, and running k0s.
- Watch for: whether they treat checkout and worker-3 as two separate problems; what they make of the two other servers' problems (worker-4, worker-2).

**T7. Send details to support.** Start: anywhere in shop-prod.
*Your support team asks for details about the problems in shop-prod. Get them what they need.*
- Success: they open "Report for support", prepare it, look at it, and download the file.
- Then ask: *Is there anything in it you wouldn't want to send?* Watch for: whether they find and trust the note that passwords and keys are left out; whether they would hide IP addresses.

**T8. A word you don't know.** Start: the problem "The server worker-3 stopped responding" (shop-staging).
*The page says two "app parts" were running on worker-3. What is an app part?*
- Success: they point at the underlined word, or open the Glossary, and explain it in their own words (a piece of an app; an app runs as several).
- Watch for: whether they notice the dotted underline at all.

## After the tasks

Hand over the questionnaire on the notes sheet (SUS, ten statements), then ask the closing questions:

1. What was the most confusing moment?
2. Which words didn't you understand, or understood only later?
3. In real life, what would you have done after this tool, and who would you have called?
4. Is there anything you expected to find, and didn't?

## Afterwards

For each session, fill in the notes sheet the same day, while you remember. When all sessions are done, list every problem seen, with how many participants had it and how bad it was:

| Severity | Meaning |
|---|---|
| 4 Blocker | A participant failed a task because of it |
| 3 Major | It took a hint, or a long detour |
| 2 Minor | It slowed them down or confused them for a moment |
| 1 Cosmetic | They mentioned it, without trouble |

**Scoring SUS:** for statements 1, 3, 5, 7 and 9, take the answer minus 1. For statements 2, 4, 6, 8 and 10, take 5 minus the answer. Add the ten numbers and multiply by 2.5: the score is 0 to 100. Around 68 is average; above 80 is good.

**Targets for this round:**
- each task done without help by at least 4 of 5 participants (or 2 of 3);
- a median of 5 or more on the 1–7 question for every task;
- a SUS median of 70 or more.

Send the filled-in sheets, the problem list and the quotes back with the code: the texts and pages are changed where people got stuck, and the tasks that fell short are tried again in the next round.

## What was fixed before the first round

An expert walkthrough of these tasks found the following, and it has been fixed:

- In Basic mode, the steps showed commands meant for whoever manages the cluster. Now Basic shows the steps written for it, and folds the others under "More checks for whoever manages the cluster".
- After a broken update, the advice now starts with undoing the update. It says that undoing is safe, and that for apps installed with Helm or Argo CD it must be done in that tool.
- The pages used words like pod, container, env, StorageClass and probe in Basic mode. A test now checks every Basic text of every rule against a list of such words.
- Some pages showed raw names like `shop/pod/web-6f7…`. They now say "app part web-6f7…" or "storage data-postgres-0".
- Problems about the same app no longer appear as "also affected" when they are about the app itself.
- History used "open · P2", and the update's changes used "env DATABASE_URL". They now read "still open · Fix today" and "setting DATABASE_URL".
- "I'm on it" said the problem stayed in the list, but the list hid it. It is now called "set aside" everywhere, and the menu's count leaves such problems out, as the list does.

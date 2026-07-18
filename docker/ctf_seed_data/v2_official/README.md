Placeholder for the official Splunk BOTS v2 questions/answers/hints
(request access via bots@splunk.com, see the "Related Projects" note in
https://github.com/splunk/SA-ctf_scoreboard).

Drop three files here, matching the schema of ../v2_writeups/:

- `ctf_questions.csv` -- Number,Question,StartTime,EndTime,BasePoints,AdditionalBonusPoints,AdditionalBonusInstructions
- `ctf_answers.csv` -- Number,Answer
- `ctf_hints.csv` -- Number,HintNumber,Hint,HintCost

Number must be a plain integer ("101", not "Q101") -- scoreboard_controller.py
does int(Number) on every code path (display, submit, hint purchase, admin
scoring) and throws on anything else. If your source material uses a
prefixed/suffixed scheme (BOTS write-ups use "Q101", "Q110-1" for
multi-part answers), strip the prefix and re-encode suffixes into the
integer itself, e.g. "Q110-1" -> 11001 (base*100 + part index) -- see
how docker/ctf_seed_data/v2_writeups/ was generated.


StartTime/EndTime must be real epoch-seconds integers, not blank -- the
controller does `int(StartTime)`/`int(EndTime)` unconditionally when checking
submission eligibility, and blank strings crash that with a Python exception
on every answer submission. Use `0` for StartTime and a real future epoch for EndTime (e.g. `1794777506`
== 120 days from when this was written, or compute your own with
`python3 -c "import time; print(int(time.time())+120*24*3600)"`) if the
event isn't actually time-boxed -- the writeups set defaults to a 120-day
window the same way.

Then run:

    ./setup.sh --v2 --ctf-questions v2-official --force

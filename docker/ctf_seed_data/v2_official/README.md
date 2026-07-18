Placeholder for the official Splunk BOTS v2 questions/answers/hints
(request access via bots@splunk.com, see the "Related Projects" note in
https://github.com/splunk/SA-ctf_scoreboard).

Drop three files here, matching the schema of ../v2_writeups/:

- `ctf_questions.csv` -- Number,Question,StartTime,EndTime,BasePoints,AdditionalBonusPoints,AdditionalBonusInstructions
- `ctf_answers.csv` -- Number,Answer
- `ctf_hints.csv` -- Number,HintNumber,Hint,HintCost

Then run:

    ./setup.sh --v2 --ctf-questions v2-official --force

Placeholder for the official Splunk BOTS v1 questions/answers/hints
(request access via bots@splunk.com, see the "Related Projects" note in
https://github.com/splunk/SA-ctf_scoreboard).

Drop three files here, matching the schema of ../v1_writeups/:

- `ctf_questions.csv` -- Number,Question,StartTime,EndTime,BasePoints,AdditionalBonusPoints,AdditionalBonusInstructions
- `ctf_answers.csv` -- Number,Answer
- `ctf_hints.csv` -- Number,HintNumber,Hint,HintCost

Then run:

    ./setup.sh --v1 --ctf-questions v1-official --force

# Cyber Kill Chain vs MITRE ATT&CK

## In one line
The kill chain describes the *stages* of an intrusion. ATT&CK catalogues the
*behaviours* attackers use. One tells me where in the story we are, the other
tells me exactly what the attacker did.

## Cyber Kill Chain
- Origin: Lockheed Martin, a linear model of an intrusion.
- Seven stages: reconnaissance, weaponization, delivery, exploitation,
  installation, command and control, actions on objectives.
- Strength: simple, and good for asking "at which stage could we have stopped
  this?" Defenders can place controls at each stage.
- Limits: assumes a mostly linear attack, focuses on the perimeter and the
  initial breach, and has little detail for what happens after access
  (discovery, lateral movement, credential theft).

## MITRE ATT&CK
- A knowledge base of adversary behaviour, built from real-world observations.
- Organised as tactics (the attacker's goal) and techniques (how they achieve
  it), with IDs such as T1110 (Brute Force).
- The Enterprise matrix has 14 tactics: reconnaissance, resource development,
  initial access, execution, persistence, privilege escalation, defense
  evasion, credential access, discovery, lateral movement, collection,
  command and control, exfiltration, impact. (Check the current version.)
- Strength: specific, comparable between attackers, and mappable to detection
  coverage. No fixed order: real attackers loop back, for example to discovery.
- Limit: it doesn't say what to prioritise, and it's large.

## Comparison
| | Kill chain | ATT&CK |
|---|---|---|
| Level | Stages of an attack | Tactics and techniques |
| Shape | Linear sequence | Matrix, no fixed order |
| Detail after access | Little | Extensive |
| Best used for | Placing defences along an attack | Describing behaviour, hunting, coverage |
| Question it answers | Where are we in the attack? | What exactly did the attacker do? |

## Practice example (from an exercise, not from my project)
Password spraying (T1110.003), then system and user discovery (T1033, T1082),
then tool download (T1105, Command and Control) and shell execution (T1059.004,
Execution). Downloading and running are two separate behaviours.


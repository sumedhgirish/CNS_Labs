# Jan 12 2018

## 4:31 AM

Bob Turley - CIO iPremier

Website is locked up. (Emails coming in one per second)

Emergency Procedure - They have a binder, they don't know where it is.

"a deficit in operating procedures" \<-- to priority acc. to CEO

### Tech

Technical architecture outsourced to QData. _Still used old tech_

Reasons for not switching

- Busy with other stuff
- Move was more expensive
- May lead to downtime
- Founder had preference to not switch because of previous circumstances.

## 4:49 AM

1. They think its NOT a simple DDoS.
1. The source is anonymized.
1. They can't be stealing credit cards - but other sensitive information is there
   on the DB.

**Hadnt check for IRP(Incidence Response Plan) and DRP(Disaster Recovery Plan)**

Who else knows - No one else.

== First action -> Call CTO for his opinion.
Should I pull the plug?
No we might loose logging data
I dont want to know that. We want keep records as proof
(It turns out there is no evidence anyways)

He is told that he needs to be given -> `provide a legal perspective`

Order is to "pull the plug".

"They won't let me into the NOC2" (Joanne)
No one relavant there to help. She can't access the network. Maybe the attack
is against thier firewall.

# The Attack

It is a synflood. This is not a proper firewall. It is an attack.

The attack is coming from 3000 sites. They start shutting down traffic
from those sites.
Shutting it down spawns 2 more zombies. They are probably using a botnet.

## The attack stops. 5:46 AM

### Should we shut down or not?

The company had been lax is protecting and securing system.

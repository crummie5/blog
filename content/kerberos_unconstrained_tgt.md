+++
title = "Kerberos Unconstrained Delegation: Compromising a Computer Object by its TGT"
date = 2020-04-12

[taxonomies]
tags = ["Windows", "Active Directory", "Privilege Escalation"]

[extra]
authors = "ATTL4S"
preview_summary = "In this post we will see how to abuse Kerberos Unconstrained Delegation to compromise systems by impersonating their associated computer accounts."
preview_image = "fig6.png"
+++

Everything that involves Kerberos functionality is such a complex subject… since I’ve been abusing these attack chains a lot recently, I thought this post would be helpful to someone.

**NOTE:** Nothing explained here is new at all. If you understand how Delegations work you may be already aware of these vectors. Nonetheless it might not be as straight forward for everyone, hence I’m writing this.

If you are not familiar with Kerberos Delegation, you can find some links in the References section as I don’t feel necessary to explain what is already perfectly explained by others.


## Introduction

Ok let’s asume we've compromised `Web01.capsule.corp`, a server with Kerberos Unconstrained Delegation enabled:

{{ figure(name="fig1.png", caption="Web01 configured with Unconstrained Delegation.") }}

<!-- more -->

At this moment we should know that if any principal - user, system, service account - connects to any of the services offered by our compromised system, it will drop a copy of its TGT unless it’s configured as a protected principal (protected users / account is sensitive). 
For example, let’s say Bulma lists the C$ share of our compromised machine. Once she does that, we will be able to dump her TGT from the resulting network session.

{{ figure(name="fig2.png", caption="Bulma listing C$ share of Web01.") }}
{{ figure(name="fig3.png", caption="Bulma's TGT in memory.") }}

As seen in [Not A Security Boundary: Breaking Forest Trusts](https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/), we also know we can use certain remote procedure calls to make arbitrary principals to connect to our Unconstrained system. In that post we saw how RPC’s MS-RPRN protocol was leveraged to obtain a TGT from an external Domain Controller. Although Microsoft fixed the issue across Forest trusts, you can still potentially abuse it within your Forest. 
If the previous technique succeeds, you can obtain a Domain Controller TGT. Since these systems happen to be replicating data to each other, becoming one of them allows you to do it aswell. This essentially translates to: using a Domain Controller’s TGT allows you to DCSync any credential you desire from the targeted domain.

Here is an example with `DC02$` from the `BADABING.SOPRANO.SL` domain (ws04.badabing.soprano.sl is the Unconstrained system):

{{ figure(name="fig4.png", caption="Dumping DC02's TGT.") }}
{{ figure(name="fig5.png", caption="Obtaining Corrado's hash through DCSync.") }}

However, in some scenarios we will notice the spooler service is disabled on Domain Controllers, or there are measures so you cannot force them to connect to arbitrary systems using the previous approach. This is the case for my other domain (`CAPSULE.CORP`).
How could I use this approach with non-DC Systems to compromise `CAPSULE.CORP`? 


## Compromising a Computer Object by its TGT

The first thing we should be aware of is that computer accounts don’t have logon permissions on any system by default. This means that if you manage to obtain a TGT for the `WS04$` computer account, you should not have any explicit access to the system represented by that same account (`Web01.capsule.corp` in this case). 
However, as we did with the Domain Controller TGT, we can take advantage of any permissions the computer account might have. There are two “general” straight forward scenarios:
- By default, computer accounts have privileges to configure Resource-Based Constrained Delegation (RBCD) for themselves. 
- Computers with LAPS installed need privileges to rotate the local administrator password, which is stored in one attribute of the computer object.

Sometimes we also see weird situations where a computer account might be a member of the Domain Admins group or happen to have random high privileges (good old Exchange). In all those situations, we can try this approach and it will likely result in a full domain compromise sooner or later.


### RBCD

Let’s say we want to compromise `WS04.capsule.corp` as it is the CEO machine. First we would make that system connect to our Unconstrained `Web01.capsule.corp` and drop its TGT. In the image below we see our desired ticket (note these network logons do not last forever, so be fast dumping the ticket. Otherwhise Rubeus has a “monitor” function to catch them easily with filters): 

{{ figure(name="fig6.png", caption="WS04$'s TGT in memory.") }}

Then we would Pass the Ticket to impersonate `WS04$` and configure RBCD. As we already compromised `Web01$`, we can use it as the trusted principal.

{{ figure(name="fig7.png", caption="Configuring RBCD with Web01 as the trusted principal.") }}

Finally we just invoke `S4U2Self` and `S4U2Proxy` to obtain valid service tickets as any user and compromise `WS04`.

{{ figure(name="fig8.png", caption="S4U2Self and S4U2Proxy as the trusted principal.") }}
{{ figure(name="fig9.png", caption="CIFS service ticket impersonating Administrator.") }}


### LAPS

With LAPS is pretty much the same. Although we cannot see the password by default, we can modify it to arbitrary values. This can be seen in the images below.

**EDIT:** As pointed out by [@_dirkjan](https://twitter.com/_dirkjan), this change is useless as the password is not stored from the LDAP attribute to SAM. My bad for being lazy and not confirming the password was working!
I will let this PoC though as it serves as another example of reaching things, even if it is useless in this case.

{{ figure(name="fig10.png", caption="WS04's LAPS password.") }}
{{ figure(name="fig11.png", caption="Modifying WS04's LAPS password.") }}
{{ figure(name="fig12.png", caption="Patatas123 4ever.") }}


## Conclusions and Mitigations

Here we have shown two interesting examples on how to compromise a system through the impersonation of its associated computer account. However, as it’s been said, there could be tons of possibilities in highly populated domains where a lot of custom groups and relatioships exist.
- Watchout the usage of Kerberos Unconstrained Delegation. It should not be necessary to use this delegation as there are really good alternatives: Constrained Delegation and RCBD.
- As a defender, always review the privileges of your principals. Not only user accounts, **EVERY** principal.
    - A really good documentation is provided by Microsoft about securing privileged access and all it involves [HERE](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material) 
- Also, review default configurations in your domain. We probably don’t want that every system can configure RBCD for itself among other risky default settings.

Hope you enjoyed this post!
~ ATTL4S



## References

- **Active Directory Security Risk #101: Kerberos Unconstrained Delegation (or How Compromise of a Single Server Can Compromise the Domain):** 
[https://adsecurity.org/?p=1667](https://adsecurity.org/?p=1667)

- **Not A Security Boundary: Breaking Forest Trusts:**
[https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/](https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/)

- **Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory:** 
[https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)

- **(Self advertising :D) Kerberos Resource-Based Constrained Delegation: When an Image Change Leads to a Privilege Escalation:** 
[https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/august/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/august/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

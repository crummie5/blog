+++
title = "Pwning A Pwned Citrix"
date = 2020-01-19

[taxonomies]
tags = ["Linux", "Exploiting", "Malware"]

[extra]
authors = "Acap4z"
preview_summary = "How what looked like a Citrix CVE-2019-19781 mitigation ended up being the NOTROBIN Trojan protecting itself from being re-exploited. The journey of exploiting a race-condition to gain RCE."
preview_image = "fig7.png"
+++

**Hello H4x0rs!**
At this time you surely have heard about the new and dangerous Citrix vulnerability labeled as CVE-2019-19781, consisting in a Directory Traversal plus Remote Command Execution attack vector. During a real security engagement I had to face a peculiar situation related to this and I wanted to share it with you, hope you find it useful.

Just as a quick recap, CVE-2019-19781, also known as “Shitrix” takes advantage of how the Citrix Gateway appliance handles templates. You can create a template by making a call to the `/vpn/../vpns/portal/scripts/newbm.pl` endpoint and inserting some Perl template into an XML file. This one contains the payload, but it is not executed until a request is made to the `/vpn/../vpns/portal/<xml_name>.xml` endpoint, which is the action that triggers the command execution.

There are a few exploits available to the public that implements that process so that you only have to specify the target and press enter to get a shell. However none of these worked for me for a good reason that we are going to explore in the following lines.

<!-- more -->

First of all I did a quick check by requesting to `/vpn/../vpns/cfg/smb.conf`. A possitive result in this test meant that the target was vulnerable to Path Traversal.

{{ figure(name="fig1.png", caption="The server is vulnerable to Path Traversal.") }}

Great! If Path Traversal works, then so will do the RCE part – I thought. So I picked the [bash version](https://github.com/projectzeroindia/CVE-2019-19781) of this exploit and launched it without success.

{{ figure(name="fig2.png", caption="The prelude of “This won't be so easy”.") }}

Given this result, I decided to investigate the web calls involved manually using Burp. The first one generates the XML with bookmark data specified in POST parameters. Path Traversal is needed both in the URL to reach the newbm.pl endpoint and in the NSC_USER to save the XML in the proper path. The server responded with the `Bookmark Added.` message, so I supposed this step was working.

{{ figure(name="fig3.png", caption="Path Traversal write attempt.") }}

At this point two possibilities came to my mind: write permissions were stripped from the vpns folder or a black/white list was in place as a hotfix to mitigate the vulnerability. To test the first hypothesis, my workmate @edhx0 suggested me to make a request to rmbm.pl. This call was designed to remove the bookmarks by cleaning the inner XML contents, but not removing the file itself (thus overwriting the contents).

{{ figure(name="fig4.png", caption="XML file without bookmarks.") }}

It seemed that we had write permissions, which meant the problem was something related to the newbm.pl call. Instead of inserting the full payload into the title POST parameter I just left it empty. The result was that in this case the XML was generated, confirming that we had a blacklist in place.

{{ figure(name="fig5.png", caption="XML file with bookmarks.") }}

I could have tried with the newbm.pl and an empty title directly instead of calling the rmbm.pl endpoint. However, I did find this test useful just in case there were more countermeasures applied to the newbm.pl endpoint, which is the one abused by the RCE exploits.
The bash script implemented the following payload:
```perl
[% template.new({'BLOCK'='exec(\'$2 | tee /netscaler/portal/templates/$filenameid.xml\');'}) %]
```

I just used the trial-and-error procedure by removing special chars and keywords from this payload until the XML was returned, instead of the `The requested page was not found on this server` error message. Finally I discovered that the keyword `BLOCK` was the only one preventing the payload to be executed. I tried to encode the keyword in multiple ways, I also tried to implement another way to execute things using [Perl Template Toolkit](http://www.template-toolkit.org/docs/manual/Directives.html), but the most I could achieve was a Perl error.

{{ figure(name="fig6.png", caption="In the common tongue it reads: “perl error - EVAL_PERL not set”.") }}

It was at this moment when I knew, I fu\*\*\*d up... or maybe not. I had already confirmed that XML writing was possible, and that the Perl environment was enabled. What if this countermeasure was just inspecting XML files in such a way they were removed if they contained naughty keywords? If this was the case I could try to request the XML file before it was actually removed. For example, I could try to issue 50 concurrent requests to the XML at the same time I was issuing the bookmark creation requests, hoping one of these 50 requests would catch the XML in time, ultimately triggering the payload. This first payload was just to retrieve the ns.conf file with some cached configurations.

{{ figure(name="fig7.png", caption="Results must be written to the XML in order to read them.") }}

Before making something elaborated, I first tried using Burp Intruder with little hope. However everything went better than expected and some lengthy responses were returned in a few requests. The race condition was exploitable!

{{ figure(name="fig8.png", caption="Pretty lucky to get this work with Intruder.") }}

At this point I was at one step to get the reverse shell. The appliance I was auditing did not have python or Netcat installed, and I could not use typical reverse shell payloads because some special characters such as `>`, `&` or double quotes. This shortcome was already treated in the Python version of the exploit using “print readpipe”, but I decided to change the payload to an `eval` expression in Perl with the `chr()` concatenation technique, which included a [Perl reverse shell payload](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet):

{{ figure(name="fig9.png", caption="No, this is not the real IP I used.") }}

The encoded payload could then be inserted into the Perl Template, bearing in mind the double-escape in the inner quotation marks.

{{ figure(name="fig10.png", caption="Seems like a monster but it is just the encoding.") }}

Repeating the race condition procedure with this payload finally led me to the reverse shell:

{{ figure(name="fig11.png", caption="The Ultimate Reverse Shell.") }}

# The truth behind

Two days after I found out this way to bypass these protections, my workmate 0xedh showed me a [post from FireEye](https://www.fireeye.com/blog/threat-research/2020/01/vigilante-deploying-mitigation-for-citrix-netscaler-vulnerability-while-maintaining-backdoor.html) revealing that a piece of Malware called NOTROBIN was infecting vulnerable Citrix appliances on the wild. One of its features was to prevent other exploitation attempts by removing XML files containing the “BLOCK” keyword in the templates folder. What a concidence! So what I thought to be our customer’s countermeasures against exploitation, it turned out to be a trojan protecting itself, but not well enough to prevent a Pwn against the Pwned Citrix.

{{ figure(name="fig12.png", caption="The NOTROBIN backdoor running.") }}

The official mitigation steps are more robust than this and can be reviewed in the [Citrix Support page](https://support.citrix.com/article/CTX267679).
And remember: if you find a Citrix appliance showing the `The requested page was not found on this server.` when launching the exploits in your legal under-contract assessment, not everything is lost. You can go through the real “Path Traversal + Race Condition + File Write + Command Execution” process to get your shell!

Be gentle.
@arcocap4z

## Aknowledgements

- All the Crummie5 for reviewing this post and covering my fool tracks.
- [@0xedh](https://twitter.com/0xedh) for the information provided and his support.

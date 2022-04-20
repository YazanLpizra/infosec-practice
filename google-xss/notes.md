# XSS Notes

* pretty much like sql injection but for html/js
* when DOM is updated dynamically, try using HTML5 events (`autofocus onfocus="alert()"` is a dope hack)
* Use this snippet to pause before page redirects: `window.addEventListener("beforeunload", function() { debugger; }, false)`

## xssgame.com Answers

### 1: Plain JS Foogle

A simple search tool that just displays a message that `Sorry, no results were found for <b> {{user input}} </b>`. just query for `<script>alert()</script>` and the JS will get inserted as-is
### 2: Timer

HTML has `onload="startTimer('<user input>');"`. pass in `1');alert('1` so that html looks like `onload="startTimer('1');alert('1');`

### 3: Cat Gallery

In `chooseTab()`, html is built dynamically: `html += "<img src='/static/img/cat" + name + ".jpg' />";` update url fragment with:
```
1.jpg' onload="alert()" onerror="alert()" type='/static/img/cat
```
 such that html looks like 
 
```
html += "<img src='/static/img/cat" + "1.jpg' onload="alert()" onerror="alert(123)" type='/static/img/cat" + ".jpg' />
```
* Note: This is kinda finicky - sometimes it works and sometimes the app returns an error: `You executed an alert, but the server side validation of your solution failed.`

### 4: Google Reader

the email input is a red herring, and the interstitial redirect page is where its at. the signup page's submit button redirects to `/confirm?next=welcome` and the interstitial page runs `setTimeout(() => window.location = '<user input>'`. this takes advantage of the fact that you can type `javascript:<js code>` in the address bar to run the JS: 

`{{ url }}/confirm?next=javascript:alert()`

### 5: Angular JS Foogle

Turns out this one is quite simple. Apparantly manually setting the value on a form field is an XSS attack vector in AngularJS (or if it limited to calling functions defined on `$scope`? im thinking this is unlikely and  can't get `{{query=10}}` to work, but the `$scope.alert = window.alert;` line is suspicious). So looking at the page's HTML and JS, we can see that there are 3 form fields: `query`, `utm_compaign`, and `utm_term`. the `query` field is handled by `ngModel` as opposed to manual JS, so that leaves the `utm_compaign` and `utm_term` fields - both of which accept input from query params using the same name. simply passing `{{alert()}}` as the value for a `utm_term` or `utm_campaign` param should work:

`{{ url }}/?utm_term={{alert()}}`

Not sure why a sandbox escape exploit didnt work here:
~~A quick look at the page source indicates we are using Angular v1.5.8. We can look up vulnerabilities for that version of angular and inject them appropriately. According to the PortSwigger XSS cheatsheet, we can use `{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}`.~~

### 6: Angular JS (1.2) Foogle

playing around a bit, you can see that the form's `action` url submits to itself and gets updated with each url change. we can try the previous payload here using a `query` query param:

`{{ url }}/?query={{alert()}}`

and we see that the form url has updated:

`<form action="/f/rWKWwJGnAeyi/?query=alert()}}" ...>`

but it dropped the leading `{{` in the payload. We can try url encoding, but no dice. but if we try html escaping by looking up character references [here](https://dev.w3.org/html5/html-author/charref), we see that `&lcub;` is an escaped `{`, so we can try a new payload:

`{{ url }}/?query=&lcub;&lcub;alert()}}`

and it works!

### 7: Content Security Policy Blog

First, since this is a CSP challenge, lets check the CSP in the headers:

`content-security-policy: default-src https://www.xssgame.com/f/wmOM2q5NJnZS/ https://www.xssgame.com/static/`

By poking around, we can see that cycling through the tabs updates a `menu` query param. it also sends us back a small JSON snippet that contains the page title. the param values have trailing `=` so its a safe bet that they are b64 encoded, and if we decode them we see they are indeed. passing in a dummy value takes us to a page that says `Error, no such menu : <user input>`. if we browse the source code, we can see that the page takes the title and injects it into the page. if we try encoding `<script>alert()</script>` and passing the encoded value as the `menu` query param we get our first useful error in the dev console (Chrome):

`?menu=PHNjcmlwdD5hbGVydCgpPC9zY3JpcHQ+`

> Refused to execute inline script because it violates the following Content Security Policy directive: "default-src https://www.xssgame.com/f/wmOM2q5NJnZS/ https://www.xssgame.com/static/". Either the 'unsafe-inline' keyword, a hash ('sha256-S8S/VNmXuUuoIR6OhqBqwIiIkuCxXq31hCCHAHnicV8='), or a nonce ('nonce-...') is required to enable inline execution. Note also that 'script-src' was not explicitly set, so 'default-src' is used as a fallback.

Reading through [this article](https://bhavesh-thakur.medium.com/content-security-policy-csp-bypass-techniques-e3fa475bfe5d#8dc8) is helpful and gives good context of the problem to tackle. Though Scenario 6 mentions that `jsonp` endpoints can be an attack vector.. reading through the following (and the linked links) is really helpful to get a better understanding of what/how/why `jsonp` works:
* https://stackoverflow.com/questions/2067472/what-is-jsonp-and-why-was-it-created
* https://en.wikipedia.org/wiki/JSONP

it seems the `/jsonp` endpoint that serves the json snippet could be significant. We can pass a `callback=someString` query param to the `/jsonp` endpoint ro speficy the name of the callback we want the server to send back:
```
{{ url }}/jsonp?menu=cats&callback=alert

// returns: alert({"title":"Cats","pictures":["cat2.jpg","cat3.jpg"]})
```

The solution is to take advantage of the `jsonp` endpoint and the error page. if we construct a payload and leverage the endpoint to inject a script tag into the error page, we should be golden:

`<script src="jsonp?callback=alert()"></script>`

then base64 encode it and set it as the `menu` query param:

`{{ url }}/?menu=PHNjcmlwdCBzcmM9Impzb25wP2NhbGxiYWNrPWFsZXJ0KCkiPjwvc2NyaXB0Pg==`
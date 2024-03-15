# Data Siege

Data Siege is a medium forensics challenge from the Cyber Apocalypse 2024 CTF by HackTheBox. 

### Enumeration

We are given a packet capture - `capture.pacp`. Opening this in wireshark, we can find that this is a relatively small capture (124 packets), that contains mainly TCP traffic with some HTTP traffic as well. Looking at the HTTP traffic, we find just three requests to IP address 10.10.10.21.

![Attachments/Pasted image 20240314214606.png]

There are two requests to an endpoint with a seemingly random name, as well as a request to get a file named `aQ4caZ.exe`. This is particularly interesting, so let's take a closer look. In the response, we can see that the media type is indeed `application/x-msdownload`, indicating that this is a binary file. So we will export this file to our disk using the `Export Objects` function of wireshark.

![Pasted image 20240314215305.png]

The file we want to download is right there and easy to find, but if the filename was mangled in some way we can always reference the packet number (56) to find the correct file.

We will hold off on analyzing that binary for now, let's look at the rest of the traffic. 

Immediately following the last GET request and exe download, we can see that the local host is beginning to communicate to port 1234 on the remote host (IP address 10.10.10.21).

![Pasted image 20240314215826.png]

Considering that we just saw an executable download, we can start to formulate a theory on what might be happening. It is likely that the binary that was just downloaded has been executed, and is now reaching out to the remote host. Let's inspect the TCP stream to see if this can be confirmed.

![Pasted image 20240314220032.png]

Right away this might not be what we expected to see, but soon we will realize that this is encoded or encrypted traffic between our two hosts. We have what, at first glance, looks like base64 encoded traffic. Taking a string and decoding it shows that unfortunately this won't be so easy.

![Pasted image 20240314220416.png]

Obviously this traffic is encrypted.

Let's turn our attention back to the executable that we downloaded earlier.

Performing a file command on the binary shows that this is a PE32 executable for Windows, but most importantly, it is written in C# using the .NET framework.

This is great news because we have access to tools that allow us to see exactly what the source code is.

Let's transfer this over to an instance of FlareVM and open it up in dnspy.

![Pasted image 20240314221050.png]

Now we can see what this is and what it is doing. 

We can first note that this is named `EZRATClient` and is currently version 0.1.6.1

Looking up ezratclient brings us to a github link where the original project is stored. This would be extremely helpful if we were unable to fully decompile the binary and see the source code.

Taking a closer look at the functions shows that we have access to the source code of the decrypt function.

![Pasted image 20240314221837.png]

Armed with this functionality, we should be able to easily decrypt the encrypted communications that we saw earlier in the network capture.

We could transcribe this into python (which is a good exercise), but we can also utilize dnspy to use the binary itself to decrypt it's own communications.

With dnspy, we are able to edit a copy of the source code, and subsequently compile and run the program.

We will head over to the main function and delete the original malware functionality so it does not execute on our machine, and instead write a quick while loop that takes user input and passes it to the Decrypt function, printing it to the console.

`NOTE: If you are writing your own decrypt script, the encryption key can be found in the Constantes Util. You can find this by going to the decrypt function and following the Constantes reference until dnspy points you to the key`

![Pasted image 20240314222853.png]

Now we can start to decrypt the communications found in the network capture.

Let's paste in the first command:

`24.1BhuY4/niTopIBHAN6vvmQ==`

![Pasted image 20240314223400.png]

This gives us an error, but the malware developer was kind enough to provide an error statement - using the error statement as a hint, we can see that the `24.` at the head of this string is what's erroring the function

Actually, if we look at other pieces of the code, this `24.` is actually denoting the character length of the encrypted command.

Trying again without the `24.`:

![Pasted image 20240314223708.png]

We can see that the command is getinfo.

Let's take a look at the response:

![Pasted image 20240314223822.png]

Interesting, it is returning quite a lot of information about the current host. getinfo isn't a standard command in the Windows OS, so it must be something custom written in the code. We can find this in `EZRATClient.Core.CommandParser`:

![Pasted image 20240314224343.png]

Now that we know how it is executing commands, let's return to decrypting the communications:

```
Request:
G4zEKBYS3iw2EN5dwLm6+/uQktBYty4nNBdsBxIqyb8=

$ cmd;C:\;srv01\svc01

Response:
ZKlcDuS6syl4/w1JGgzkYxeaGTSooLkoI62mUeJh4hZgRRytOHq8obQ7o133pBW7BilbKoUuKeTvXi/2fmd4v+gOO/E6A0DGMWiW2+XZ+lkDa97VsbxXAwm0zhunRyBXHuo8TFbQ3wFkFtA3SBFDe+LRYQFB/Kzk/HX/EomfOj2aDYRGYBCHiGS70BiIC/gyNOW6m0xTu1oZx90SCoFel95v+vi8I8rQ1N6Dy/GPMuhcSWAJ8M9Q2N7fVEz92HWYoi8K5Zvge/7REg/5GKT4pu7KnnFCKNrTp9AqUoPuHm0cWy9J6ZxqwuOXTR8LzbwbmXohANtTGso6Dqbih7aai57uVAktF3/uK5nN7EgMSC0ZsUclzPZjm0r4ITE2HtBrRXJ78cUfIbxd+dIDBGts7IuDfjr0qyXuuzw+5o8pvKkTemvTcNXzNQbSWj+5tTxxly0Kgxi5MVT0ecyJfNfdZG0slqYHKaqJCZm6ShfvGRFsglKmenBB274sBdkVqIRtodB8dD1AM1ZQQX1MBMGDeCwFqc+ahch0x375U6Ekmvf2fzCZ/IaHOHBc8p5se1oNMRbIqcJaundh5cuYL/h8p/NPVTK9veu3Qihy310wkjg=

$ cmd;C:\;echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwyPZCQyJ/s45lt+cRqPhJj5qrSqd8cvhUaDhwsAemRey2r7Ta+wLtkWZobVIFS4HGzRobAw9s3hmFaCKI8GvfgMsxDSmb0bZcAAkl7cMzhA1F418CLlghANAPFM6Aud7DlJZUtJnN2BiTqbrjPmBuTKeBxjtI0uRTXt4JvpDKx9aCMNEDKGcKVz0KX/hejjR/Xy0nJxHWKgudEz3je31cVow6kKqp3ZUxzZz9BQlxU5kRp4yhUUxo3Fbomo6IsmBydqQdB+LbHGURUFLYWlWEy+1otr6JBwpAfzwZOYVEfLypl3Sjg+S6Fd1cH6jBJp/mG2R2zqCKt3jaWH5SJz13 HTB{********** >> C:\Users\svc01\.ssh\authorized_keys
```

Here we have the first part of the flag, which is part of an effort to establish persistence by writing the attackers public key to the authorized_keys file for user `svc01`

Continuing:

```
Request:
3BQcww/tA6Mch9bMGZk8uuPzsNLBo8I5vfb3YfHJldljnkES0BVtObZlIkmaryDdqd0me6xCOs+XWWF+PMwNjQ==

$ cmd;C:\;type C:\Users\svc01\Documents\credentials.txt

Response:
zVmhuROwQw02oztmJNCvd2v8wXTNUWmU3zkKDpUBqUON+hKOocQYLG0pOhERLdHDS+yw3KU6RD9Y4LDBjgKeQnjml4XQMYhl6AFyjBOJpA4UEo2fALsqvbU4Doyb/gtg

$ cmd;C:\;Username: svc01
Password: Passw0rdCorp5421

2nd flag part: ************
```

Got the second flag part!

And further down in plain text, we have an encoded powershell command:

![Pasted image 20240314230038.png]

After decoding the command:

![Pasted image 20240314230233.png]

We find the third flag in a powershell command that establishes persistence by creating a scheduled task to execute `4fva.exe` daily at 2am.

We now have all the parts, so we can concatenate these to obtain the full flag!

### Initial Foothold

Let's also take a quick look back at the beginning of the network capture. There is some traffic directed to port 61616.

Looking up port 61616 in a search engine shows results for an application called `ActiveMQ`. The headers for this traffic can be found by following the TCP stream for the traffic:

![Pasted image 20240314232502.png]

We can see that the version number is `5.18.2`. Searching for known vulnerabilities in ActiveMQ, we find CVE-2023-46604, which this version is vulnerable to. More information can be found at https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46604

The attacker was able to exploit this CVE which allowed them to install a remote access tool and establish two forms of persistence.
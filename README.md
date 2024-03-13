# Understanding-Log-Sources-Investigating-with-Splunk

In this project, I analyze a vast dataset of over 500,000 events, which includes a variety of attacker Tactics, Techniques, and Procedures (TTPs). I use the robust SIEM tool, [Splunk Enterprise](https://www.splunk.com/en_us/products/splunk-enterprise.html). My project aims to:

1. Utilize a wide array of Search Processing Language (SPL) tools to create intricate and efficient searches: [Exploring Splunk and SPL](#exploring-splunk-and-spl)
2. Create effective intrusion detection searches and alerts based on:
    1. Attacker TTPs and known behavior: [Detecting Attacker TTPs](#detecting-attacker-ttps)
    2. Anomaly detection: [Detecting Attacker Behavior with Anomaly Detection](#detecting-attacker-behavior-with-anomaly-detection)
3. Identify various elements, methods, and processes involved in an attack to construct a timeline detailing how the attacker initially gained access. [Intrusion Detection With Splunk](intrusion-detection-with-splunk) -> [Finding the Source of the Intrusion](#finding-the-source-of-the-intrusion)

This project has equipped me with a thorough understanding of Splunk's architecture. I've developed numerous detection-focused SPL searches and applied both attacker tactics and analytics for defensive cybersecurity tasks. As a result, I feel confident in my ability to effectively utilize Splunk for real-world log analysis, detection, and incident response.
## Table of Contents

- [Exploring Splunk and SPL](#exploring-splunk-and-spl)
    - [Splunk as a SIEM](#splunk-as-a-siem)
    - [Identify Available Data](#identify-available-data)
    - [Practice Queries](#practice-queries)
- [Splunk Applications - Sysmon](#splunk-applications---sysmon)
- [Intrusion Detection With Splunk](#intrusion-detection-with-splunk)
    - [Search Performance Optimization](#search-performance-optimization)
    - [Using Attacker Mindset](#using-attacker-mindset)
    - [Meaningful Alerts](#meaningful-alerts)
    - [Further Detection Practice](#further-detection-practice)
- [Detecting Attacker TTPs](#detecting-attacker-ttps)
    - [Crafting SPL Searches Based on Known TTPs](#crafting-spl-searches-based-on-known-ttps)
    - [Practice Investigation](#practice-investigation)
    - [Detecting Attacker Behavior with Anomaly Detection](#detecting-attacker-behavior-with-anomaly-detection)
    - [SPL Searches Based on Analytics](#spl-searches-based-on-analytics)
    - [Practice Scenario](#practice-scenario)
- [Finding the Source of the Intrusion](#finding-the-source-of-the-intrusion)
    - [Find the process that created remote threads in rundll32.exe](#find-the-process-that-created-remote-threads-in-rundll32exe)
    - [Find the process that started the infection](#find-the-process-that-started-the-infection)

## Exploring Splunk and SPL
This section focuses on utilizing Splunk's SIEM capabilities and exploring its various data analysis tools using the Splunk Processing Language (SPL).

### Splunk as a SIEM
To begin with basic SPL commands, I set up a VM host with a Splunk Index named **main**, containing Windows Security, Sysmon, and other logs.

Starting with a simple query, I searched the index for the term "UNKNOWN" using `index=main "UNKNOWN"`:

![Splunk1](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/b057b3f1-9111-41ef-a210-aa8141732a33)

Next, I modified the query to include wildcards and find all occurrences of "UNKNOWN" with any number of characters before and after it:

![Splunk2](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/5d64d5c6-6cdd-43a2-9565-5f15ec1514d3)

The use of wildcards expanded the search results as the criteria became less strict.

Splunk automatically identifies data fields from the events such as source, sourcetype, host, and EventCode. For example, from the previous search, I could see some of the hosts that were found:

![Splunk3](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/81903c1c-ad24-45df-bd06-03d4ebe64fd4)

I then created queries using these data fields combined with comparison operators to filter based on the values found for each data field. For instance, I searched for all records where the host is "waldo-virtual-machine" using `index="main" host="waldo-virtual-machine"`:

![Splunk4](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/15e7ec3a-fef5-4f8e-9135-d7206d27c5b7)

Using a pipe | I directed the output of a search into a command, similar to Linux. For manipulating data fields, SPL offers a **fields** command that can be used to remove and add filters from the results.

With the fields command, I conducted a search on all Sysmon events with EventCode 1 but removed the "User" field from the results. This filtered out all the results where the user initiated the process:

![Splunk5](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/f4be6fd2-19ea-4647-948a-5dc34321c0cb)

Another useful command is **table** which can be used to change the display of the results into a table with the desired columns.

With the Sysmon EventCode 1 results, I created a table that only displayed the time, host, and image fields:

![Splunk6](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/d38b3a7f-5a70-488d-bab0-02e1818ed220)

If I wanted to use a different name for a field, I could use the **rename** command to change it in the results. For example, I changed the Image field to be "Process":

![Splunk7](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/6e51fca8-acd9-4818-8612-30a27c5b2f29)

![Splunk8](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/166e008a-cab2-4acc-899f-b87a575eda10)

Another helpful command is **dedup** which deletes all duplicate events based on a specified field. In the previous results where I renamed Image to be Process, each value had many counts, but many of them were filtered out with dedup:

![Splunk9](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/b6dd5453-dfd2-476c-8686-893788f5f5a2)

Using the **sort** command, results can sorted in ascending or descending order based on a specified field. Here, I sorted the results by the time they occurred and in descending order to see the most recent results:

![Splunk10](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/8700cf9e-103a-4710-8788-520b42bbc934)

The **stats** command allows the user to compute statistical operations towards the results for organization purposes. Using the **count** operation, I compiled the results to show the number of times that each Image created an event at a certain time:

![Splunk11](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/d9b79d17-3986-4423-a591-2f2f840c7d97)

To further expand on the data visualization aspect of SPL, there is the chart **command** that is very similar to stats but outputs the results into a table-like data visualization.

I created a chart with the previous example of taking the count of events that an Image created at a specific time:

![Splunk12](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/8ed41278-d441-45e5-9f1e-734c3b5f35db)

If I needed to further redefine or create a new field from an existing field, I could use the **eval** command. For example, if I wanted the output of the Image field but in all lowercase, I could create a new field and set its results to the lowercase version of Image.

`eval Process_Path=lower(Image)` would create a new field called "Process_Path" and uses the lowercase function with the Image field as input to set the new field equal to the lowercase results of the Image field:

![Splunk13](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/c84bb4f2-de78-4efd-b8ef-aacbeba13b36)

I could also extract new fields from existing ones using regular expressions through the **rex** command.

`[^%](?<guid>{.*})` is a regular expression that: 
- Excludes anything that starts with %
- Creates a named capture group called "guid" that assigns the name to anything in between curly braces and isn't a new line character

This would create a new field called "guid" that I could then use in further commands. Using the new field, I would create a table that shows all the extracted data:

![Splunk14](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/911198ec-2796-4b5d-bbef-6811c40f2705)

Splunk **Lookups** can add to the results of a query by matching fields in the results to fields in lookup files.

I created a file called malware_lookup.csv that holds fields matching files to whether or not they are malware. This acted as a lookup table file that I could use with the data to do a lookup on known malicious files.

![Splunk15](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/1a9e2f1d-ae6f-45fc-a4ae-29b7567f42af)

After adding malware_lookup.csv to the Lookup files in Splunk's settings, I was ready to use it with the **lookup** command.

First, I did some results manipulation by extracting all the names of the files listed in the Image field, converting them to lowercase, and then storing the results into a new field called "filename":

`| rex field=Image "(?P<filename>[^\\\]+)$"` = extract new filename field 
`| eval filename=lower(filename)` = converts all of the results for the filename field to lower case

Now, I could compare the values of the new filename field to the malware_lookup.csv (which has a matching filename column) to see if any of the found files are known malware.

`| lookup malware_lookup.csv filename OUTPUTNEW is_malware` = uses the newly created filename Splunk field as a key to lookup the column filename in malware_lookup.csv and then outputs the corresponding "is_malware" value into a new Splunk field with the same name 

With these commands, I had extracted all the filenames found in the Splunk Image field and compared them against a list of known malicious files to see which ones were found in my data:

![Splunk16](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/23a20e0d-63a9-437f-9ec8-c52da289896f)

There is an alternate way I could have done, a command which replaces the rex with **mvdedup** and **mvindex** to split the full file paths by backslashes and take the last index, which is the filename.

`eval filename=mvdedup(split(Image, "\\"))` = split up the file names from the Image field using the backslashes and remove any duplicates

`eval filename=mvindex(filename, -1)` = select the last index which will be the filename 

The rest is similar to the rex version minus the duplicates, and the results are the same:

![Splunk17](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/63d70b0c-e00e-4a6b-a85e-6be2e34d6aaa)

Transactions in Splunk are used to group events that share common characteristics. With the **transaction** command, I can group events based on certain fields like Image.

`| transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m` = creates a transaction of events within 1 minute of each other that start with an event with EventCode 1 and ends with an event with EventCode 3

After removing the duplicate values, I can identify programs that all created certain types of events within 1 minute of each other:

![Splunk18](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/c8c129e2-bbc7-4122-b225-6676e0440961)

Finally, I use SPL's capability to do subsearches to filter out large sets of data. I start by creating a very simple search to get all Sysmon events with EventCode 1.

Using the logical NOT keyword, I can filter out all the results of a subsearch from the results of this main search:

```
NOT
	[ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
	| top limit=100 Image
	| fields Image ]
```
The subsearch identifies all Sysmon events with Event Code 1 and returns the 100 most common values of the Image field. Consequently, these results are excluded from the main search:

![Splunk19](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/f9ec7f46-6c51-4fab-ba6d-80bac01eefe3)

Filtering out these events provides insight into some of the Event Code 1 events that showcase more rare and unique instances of programs being used.

### Identify Available Data

To gain an overview of all the indexes in my dataset, I utilize the **eventcount** command with summarize=false to generate a table of each one:
![Splunk20](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/5ed92d41-7c97-4dde-af52-b161356ea6c2)

Next, I employ the **metadata** command to examine all the different sourcetype objects (i.e Sysmon) that have generated events in my data:

![Splunk21](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/735cc2ce-9045-4023-8d1d-70c325d82bd0)

Similar commands can be used to view all the hosts and gather information about the sources:

![Splunk22](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/d9a3ed0d-6a7b-478c-94b6-f966368d1c61)

![Splunk23](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/f2d87bee-fa05-4472-8682-28501320e727)

Once I have identified the different sourcetypes, I can view their raw event data in a table using `table _raw`:

![Splunk24](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/b7c2c0c2-9504-46f5-adeb-22e58a0f727f)

For information about the types of fields a sourcetype has, I utilize the **fieldsummary** command:

![Splunk25](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/77d06c23-eb36-47ac-a6c8-44d92609bc4f)

Further filtering of the results can be done based on some of the returned statistics from fieldsummary:

![Splunk26](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/861c1cd0-a8c1-423e-81ba-386be3e5e83a)

For time-based queries, the **bucket** command can group events together, and then computing statistics on them makes it easy to view summaries of defined time periods. In this query, all events are bucketed into singular days, and the counts of each sourcetype in each index are computed:

![Splunk27](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/f3aa537a-cba2-484a-a321-aed40326ce88)

Another method to find uncommon events is with the **rare** command. Here, the top 10 least common combinations of index and sourcetype are retrieved:

![Splunk28](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/0ee32858-0b40-4b74-a8d3-f1502405a124)

The **sistats** command can also be used to explore event diversity and extract information about common/uncommon events. This command counts the number of events based on index, sourcetype, source, and host to provide a big picture analysis of the events:

![Splunk29](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/07ba6ec9-63b4-45a0-8179-d17464b2c453)

### Practice Queries

#### Find the account name with the highest amount of Kerberos authentication ticket requests

Given that the specific Event Code for Kerberos authentication ticket requests is unknown, I initially perform a simple search for "kerberos authentication" to identify it as 4768:

![Splunk30](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/aecb2357-8453-4d84-81a5-3b451bb9e376)

Subsequently, I execute a search on Event Code 4768 that counts all the Account_Name field values, places them into a table, and sorts them to determine the account with the highest count:

![Splunk31](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/04e8f79a-e07d-4a47-af8c-c1c0284164c0)

The account named "waldo" has the highest number of Kerberos authentication requests.

#### Find the number of distinct computers accessed by the account name SYSTEM in all Event Code 4624 events

For this more specific query, I instantly retrieve the information by selecting all events with Event Code 4624 and the Account_Name SYSTEM, then utilizing dedup to obtain all the unique ComputerName values:

![Splunk32](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/62fdbd18-0ac9-4edd-aef7-42a0deed9448)

This query returns 10 results, indicating that the SYSTEM account accessed 10 unique computers in the 4624 events.

## Splunk Applications - Sysmon

To showcase the practicality and functionality of Splunk applications, I'll be utilizing the [Sysmon App for Splunk](https://splunkbase.splunk.com/app/3544).

After downloading the app into my Splunk Enterprise instance, I can confirm its functionality and access all its tools from the toolbar:

![Splunk33](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/0891c825-6dfb-4bda-a0e0-c37baa73eb8f)

Within the **File Activity** section, I can examine all the files created within my dataset:

![Splunk34](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/d122f524-866c-4c37-8777-83249aa63473)

However, the "Top Systems" section does not display any data because the default search used by the app is not compatible with my dataset:

![Splunk35](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/1c17e50b-f560-4a68-87c2-9d44c09d5324)

To address this, I manually edit the search within the UI to align it with my data, ensuring it functions as a standard Splunk search would.

The original search was `sysmon EventCode=11 | top Computer`, but since my data does not contain a field named "Computer," I modify it to "ComputerName" to accurately reflect my dataset:

![Splunk36](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/0c26345f-1b88-4ac9-8879-74470287362b)

As a result, the "Top Systems" section now displays accurate data because the underlying search produces results:

![Splunk37](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/c669fd27-a484-4225-95d1-d95239f6b996)

Instances like the above example highlight that downloaded apps may not always perfectly align with your dataset in terms of keywords and fields. I proceeded to make additional adjustments to some of the searches used by the **Sysmon App for Splunk**.

For example, the app included a report to showcase the number of network connections made by an application. However, many of the fields and search terms used were incompatible with my dataset:

![Splunk38](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/14c3e940-0484-4dbc-aa56-e3c5c6cdc584)

To enhance the functionality of this search, I modified it to accurately display the number of network connections made by the **SharpHound.exe** application. 

While there were several fields to edit, such as protocol, dest_port, dest_host, and dest_ip, I successfully identified that the SharpHound app had made 6 network connections:

![Splunk39](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/731817bb-a0c8-432a-be67-79eadbaeabd4)

## Intrusion Detection With Splunk

This section will delve into real-world intrusion detection scenarios, simulating the techniques that blue teams use to hunt for attacks within an organization. I'll employ common techniques to identify various types of attacks present in the dataset, which contains over 500,000 events.

### Search Performance Optimization

To start, I'll focus on identifying attacks in the Sysmon data. First, I'll use a simple command to determine the number of events for Sysmon:

![Splunk40](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/61bc6975-05d2-406a-a2a5-7442264a70a4)

Next, I'll compare the performance differences between SPL searches by searching for the system name "uniwaldo.local" with and without wildcards:

![Splunk41half](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/8ce74ee3-b606-4ea5-8a28-10c011632d98)
![Splunk41](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/73886e37-520d-4013-9d62-4f635f02df8e)

Although both searches yield the same number of events, the search with wildcards takes significantly longer because it matches many more events.

Another example to improve performance and accuracy is to specify the field when searching, assuming the expected keyword field is known:

![Splunk42](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/5a12d616-8bed-4870-8f58-cb72a50c411f)

### Using Attacker Mindset

Sysmon event codes provide insight into the attacks that attackers use against a system or network, as each event code signifies specific processes performed on a host.

I start by examining the number of events related to each Sysmon event code in the data:

![Splunk43](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/565f9a63-4f34-479c-b397-ccc35f24fe71)

Event code 1 for process creation can indicate unusual parent-child trees, so I begin searching for attacks using this event code:

![Splunk44](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/aca2b0eb-6133-41f7-97d8-3d15f3fdd973)

Some problematic child processes are **cmd.exe** and **powershell.exe** so I look for them in a search with the Image field:

![Splunk45](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/2d3aa4bf-86ac-45ba-a356-3bff8ecda668)

This narrows down the search to 628 events compared to the initial 5,472.

Some questionable results are where the problematic child processes are spawned from a **notepad.exe** parent process:

![Splunk46](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/ffec5856-319b-4e62-937c-25fca6ad1d31)

I further narrow down the search to focus on these 21 occurrences:

![Splunk47](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/c2eba9b6-b4bc-41bf-aaa6-14aaaa1fa03f)

Examining the first event reveals a command-line prompt where PowerShell is used to download a file from a server:

![Splunk48](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/306f8d1f-3ebc-4389-9b94-19f819d44317)

Investigating the IP address that the file was downloaded from reveals only two sourcetypes:

![Splunk49](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/f49ff88f-a58f-47c5-9dd3-c949a8fe78d4)

Specifically examining the syslog sourcetype shows that the IP belongs to the host "waldo-virtual-machine" and it is using its ens160 interface:

![Splunk50](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/f9eeaa3d-04c3-4bee-b760-156c24a1b21f)

One event shows that a new address record has been created on the interface to establish some form of communication with a Linux system:

![Splunk51](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/3f9a8243-4c3f-4075-8e49-cda74969df36)

I also checked the Sysmon-related logs with the CommandLine field to investigate further:

![Splunk52](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/de60af5b-41c4-4945-ba26-b37317b90292)

These results show many commands being used to download likely malicious files, confirming that the Linux system being connected to is likely infected.

Adding the count for the host field reveals that two hosts were victims of the attack:

![Splunk53](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/d5e95146-8fb0-40a8-b494-2dc0de4a477c)

Based on the file name, it appears that one of the hosts was targeted with a DCSync attack using a PowerShell file:

![Splunk54](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/5d947e4e-d60a-4b25-9833-750b340af6d9)

This type of attack is related to Active Directory, and I can focus on this by examining events with event code 4662. I also used a couple of specifiers to show the procedures that a DCSync attack uses:

`AccessMask=0x100` = this will appear when Control Access is requested which is needed for a DCSync attack because it requires high-level permissions

`AccountName!=*$` = removes all results where the account being used is a service, so I only see instances where a user account was used for DCSync which is normally not allowed

![Splunk55](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/0baf1b31-5c83-4e5a-a670-eeb8b4ca6a08)

Examining the two returned events, I see two GUIDs:

![Splunk56](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/e3f303de-8e37-4864-b98a-14855bf49964)

The first is for "DS-replication-Get-Changes-All":

![Splunk57](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/d3e0316b-dc19-48e6-9b04-4994a090576d)

From the documentation, I see that this function is used to "replicate changes from a given NC," essentially defining a DCSync attack as it attempts to ask other domain controllers to replicate information and gain user credentials.

This information concludes that the attacker has infiltrated a system, gained domain admin rights, moved laterally across the network, and exfiltrated domain credentials for the network.

I now know that the waldo user was used to execute this attack and that the account likely has domain admin rights itself, but I am not yet aware of how the attacker gained these rights initially.

Knowing that lsass dumping is a prevalent credential harvesting technique, I conduct a search to see the types of programs related to event code 10 and the keyword "lsass":

![Splunk58](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/148cc48e-e978-4e54-83a9-09de6b1c55d9)

Assuming lower event counts can be considered out of the ordinary, or not typical behavior, I find that some of the lowest event counts are related to notepad.exe and rundll32:

![Splunk59](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/2d903306-19cf-4609-a8b2-7b48b73548da)

Further inspection of notepad reveals only one event that Sysmon thinks is related to lsass and credential dumping:

![Splunk60](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/f41f3d3a-d0db-48a8-b336-b0b5593b32a1)
![Splunk61](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/3c9c1659-5e93-460c-8b10-325fd4d07a04)

### Meaningful Alerts

In the previous section, I found that APIs were called from UNKNOWN memory regions, which eventually led to the DCSync attack I investigated. I can now create an alert to detect this behavior and potentially prevent similar attacks in the future.

First, I want to know more about the UNKNOWN memory location usage, so I search to see the related event codes:

![Splunk62](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/03274342-9c69-4ffc-929d-85129c213477)

The results show that the only related event code is 10, which is for process access. Therefore, I am looking for events that attempt to open handles to other processes that don't have a memory location mapped to the disk.

![Splunk63](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/1829fcd8-03c3-4cde-a82a-b15b3ad332d8)

Filtering out many normal instances, I start by removing any events where the source program tries to access itself, as the attack I investigated did not do this:

![Splunk64](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/131e49d6-cc4f-444d-9697-99b4f40a41e7)

To further filter the programs, I exclude anything C# related by excluding any .NET, ni.dll, or clr.dll references:

![Splunk65](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/2957ad9e-cd11-41f2-8cdd-9621ad242744)

Another instance to remove is anything related to WOW64, which has a non-harmful phenomenon that comprises regions of memory that are unknown:

![Splunk66](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/04385d60-7f7b-4874-9013-acd206ad58b5)

Explicitly removing anything related to explorer, which produces many non-malicious events, through the SourceImage field:

![Splunk67](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/eb77e16c-6c8d-43fb-98b6-667ad4075c71)

Now, I have a list of only 4 programs that exhibit the behavior I'm trying to target with my alert. I could then analyze and possibly filter out more non-threatening programs, but for now, this is an alert that could work to prevent the domain admin credential harvesting I identified earlier.

This alert has some issues, as the dataset includes very few false positives and is tailored specifically for this exercise. For example, the alert could be bypassed by simply using an arbitrary load of one of the DLLs that I excluded. However, for the purposes of this exercise, I was able to identify an attack pattern and create a targeted alert that would detect it.

### Further Detection Practice

#### Find the other process that dumped credentials with lsass

To find the other process, I go back to my finalized alert for the attack and look at some of the TargetImages:

![Splunk68](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/e99941cc-9396-45c8-9d73-f633af6e0b80)

From there, I can see that, in addition to notepad.exe, rundll32.exe was also using lsass for credential dumping:

![Splunk69](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/efcc8cbb-7fdc-4d8f-8603-e7c063d37242)

#### Find the method rundll32.exe dumped lsass

To find the method, I create a target search to see all the events that have the source program as rundll32.exe and the target program as lsass:

![Splunk70](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/8d91c5fd-184b-47a5-8386-1e7e4074f8ee)

From the search, I extract the unique call traces and find many DLLs being used. After a little research, I find that one of the DLLs, comsvcs.dll, is a common dumping DLL.

#### Find any suspicious loads of clr.dll that could be C sharp injection/execute-assembly attacks, then find the suspicious process that was used to temporarily execute code

To find suspicious loads of **clr.dll**, I start by getting an idea of all the types of events that include the phrase clr.dll. After some searching, I find that an important field to pay attention to is what processes were loading the clr.dll image:

![Splunk71](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/d12d7b75-de63-4ed4-b513-9ce031053f68)

One way that I began to filter the results was to just see which images Sysmon correlated with process injection attacks:

![Splunk72](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/9785a42a-c954-4581-bc47-71f328e8a06b)

Filtering out normal instances, I remove any events related to Microsoft processes like Visual Studio:

![Splunk73](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/076428f9-fc4e-4953-a7e2-5b64235d25c3)

Unsurprisingly, I find that both notepad.exe and rundll32.exe, from my original DCSync alert, were also used to execute code.

#### Find the two IP addresses of the C2 callback server

This is as simple as looking for any IPs that rundll32.exe or notepad.exe were connected to:

![Splunk74](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/77b60378-ddbf-4a87-86e6-b09a0c216dc1)
![Splunk75](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/73f8cab9-55f1-44a5-ba48-e26a6670a0e2)

10.0.0.186 and 10.0.0.91 appear to be the command and control servers.

#### Find the port that one of the two C2 server IPs used to connect to one of the compromised machines

I started with a broad search to see any mention of the two IP addresses:

![Splunk76](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/4ee3416a-5a79-48cb-809c-3e63025edb08)

Since in this case I only care about network connections, I filter to see all events with event code 3:

![Splunk77](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/bc397442-9e5c-4240-b72b-31851b1771bc)

Digging into one of the events gives me an idea of some of the key fields that I want to investigate further:

![Splunk78](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/d8e0830b-204c-4198-bc5f-51ecd5e20ec2)

Since I don't know which of the IPs connected to the compromised machine, I simply extract all the source IPs and their correlating destination ports:

![Splunk79](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/be266a5b-106c-40ec-9069-1dc683d2f4dd)

From these results, I can conclude that the C2 IP 10.0.0.186 used the Remote Desktop Protocol port 3389 to connect to the compromised machines.

## Detecting Attacker TTPs

Using attacker TTPs to create searches and alerts involves searching for known behavior and abnormal behavior. This section covers creating searches based on attacker behavior.

### Crafting SPL Searches Based on Known TTPs

Attackers often use Windows binaries like net.exe for reconnaissance activities to find privilege escalation and lateral movement opportunities. To target this behavior, I use Sysmon event code 1 and look for command-line usage that can provide information on a host or network:

![Splunk80](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/f1f0c222-2930-40b2-ba7d-e1e17f25b9b2)

Searching for malicious payload requests can be done by looking for requests for common whitelisted sites that attackers use to host their payloads, like **githubusercontent.com**. Sysmon event 22 for DNS queries can help me identify these occurrences.

There is a QueryName field that I can use to search for githubusercontent.com requests:

![Splunk81](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/427dc88d-b304-4f99-a2e8-35fb3af32418)
![Splunk82](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/32cff9e2-9531-4990-9663-2ed95736dcb5)

Several MITRE ATT&CK techniques use PsExec and its high-level permissions to conduct attacks. Some common Sysmon event codes that relate to these attacks are 13, 11, 17, and 18.

Leveraging event code 13, which is for registry value sets, takes a lot of involvement. However, using some resources like [Splunking with Sysmon](https://hurricanelabs.com/splunk-tutorials/splunking-with-sysmon-part-3-detecting-psexec-in-your-environment/) can provide some well crafted searches:

![Splunk83](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/7a248b06-f3c2-402d-9d86-0263f99392ac)

`index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath"` = this will isolate to event code 13, select the services.exe image which handles service creation, and grabs the TargetObject which are the registry keys that will be affected 

`rex field=Details "(?<reg_file_name>[^\\\]+)$"` = grabs the file name from the Details field and stores it in a new field reg_file_name

`eval reg_file_name = lower(reg_file_name), file_name = if(isnull(file_name), reg_file_name, lower(file_name))` = this converts reg_file_name to lower case, then modifies the file_name field so that if it is null it will be filled with reg_file_name and if not it keeps its original value and sets it to lower case as well

`stats values(Image) AS Image, values(Details) AS RegistryDetails, values(\_time) AS EventTimes, count by file_name, ComputerName` = for each unique combination of file_name and Computer name,  this will extract all the unique values of Image, Details, TargetObject, and time

This query will be able to tell me all the instances where **services.exe** modified the ImagePath value of a service. In the search results, I have extracted the details of these modifications.

Using Sysmon event code 11 for file creation shows that there have been executions resembling PsExec:

![Splunk84](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/b8636185-4209-45f5-bf96-8f4b6961d9ce)

Sysmon event code 18 for pipe connections can also show a PsExec execution pattern:


Archive or zipped files are typically used for data exfiltration, so using event code 11, I can filter for these types of file creations and see some concerning results:

![Splunk86](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/cb0cbfbe-8279-433b-a071-a7fd25531524)

A common way to actually download the payloads that attackers are hosting is through PowerShell or MS Edge while also targeting **Zone.Identifier**, which signals files downloaded from the internet or untrustworthy sources:

![Splunk87](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/05c2e662-26a0-471a-a093-cf063c423aa5)
![Splunk88](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/a4a6f53b-9aa3-420f-bac2-2ba029c2bfef)

Detecting execution from unusual places, for example, in this search, I look for process creations in the downloads folder using event code 1:

![Splunk89](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/f00bac3d-358a-44e6-945a-fc12f66ebaff)

Another sign of malicious activity is the creation of DLL and executable files outside of the Windows directory:

![Splunk90](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/7aaadfc8-e8f7-4f01-8418-aae6cb6e3a4e)

Even though it takes a bit of manual involvement, another attribute to look for is the misspelling of common programs. In this case, I look for a misspelling of the PsExec files:

![Splunk91](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/a9495219-e8a4-4db9-bfea-481607fca296)

Finally, one of the most common tactics is using non-standard ports for communications and data transfers. Searching for this can be as simple as looking for all network connections, event code 3, that aren't using typical ports:

![Splunk92](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/3ce84624-d113-4529-8ebb-0c61127a8868)

### Practice Investigation

#### Find the password utilized during the PsExec activity

This was very simple to find as the attacker often used command line arguments to enter in the password. I simply looked for any reference to the phrase "password" in Sysmon events and found a PsExec related event with the password stated in the CommandLine field:

![Splunk93](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/fd6223d0-d732-4483-a999-78100d8d5272)

## Detecting Attacker Behavior with Anomaly Detection

Rather than focusing on specific attacker TTPs and crafting searches to target them, another method of detection is by using statistics/analytics to capture abnormal behavior compared to a baseline of "normal" behavior.

Splunk provides many options to do this, including the **streamstats** command:

![Splunk94](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/567abf8a-e002-4f45-bc58-b2ccdc142d3f)

Streamstats lets me capture real-time analytics on the data to better identify anomalies that may exist. In the above example:

`bin time span=1h` = groups the event code 3 events into hourly intervals

`streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image` = creates rolling 24-hour averages and standard deviations of the number of network connections for each unique process image

These statistics create the baseline of normal behavior to which I can then extract any events that are outside of the range that I specify with: `eval isOutlier=if(NetworkConnections > (avg + (0.5 * stdev)), 1, 0)`

### SPL Searches Based on Analytics

One of the simpler ways to search for anomalies is by looking for really long commands. Attackers often need to execute complex commands to do their tasks so searching based on the length of the CommandLine field can be effective:

![Splunk95](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/d93f3d3d-3efc-4b01-a0ac-24005a9454ae)

I can also use the same technique of looking for a baseline and apply it to unusual cmd.exe activity:

![Splunk96](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/d7bce3a2-a6e5-4956-8475-1a7b9da500d7)

The above baseline is relatively simple as it looks for average/stdev of the number of commands being run with cmd.exe.

Another anomaly that is often exhibited by malware is a high amount of DLLs being loaded within a short amount of time. This can often be done by non-malicious activity as well, but it is still something to check.

Here I try to filter out as many benign processes that could exhibit this behavior and then extract all of the events where more than 3 unique DLLs are loaded within an hour:

![Splunk97](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/6d1ac1cc-5133-4025-9118-18410cd7d17a)

When the same process is executed on the same computer it can often signal malicious or at least abnormal behavior. With Sysmon event code 1 I can see all the events where the same programs are started more than once.

To do this I look for instances where a process, the Image field, has more than one unique process GUID associated with it:

![Splunk98](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/16def442-4884-427a-b37e-1192d7222074)

Looking at some of the previously found malicious programs I can see that this behavior was related to some of the lsass dumping activity:

![Splunk99](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/4d1498ce-66ed-41ce-95ce-a655c3f722e1)

### Practice Scenario

#### Find the source process image that has created an unusually high number of threads in other processes (greater than 2 standard deviations)

To start looking for this process, I first want to know more about the events that I should be looking for. Sysmon event code 8 is for remote thread creation so I check all of these events where the SourceImage field is not the same as the TargetImage:

![Splunk100](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/36ce25b5-a7ec-47f4-b0df-4bd474a08c51)

Then, using a similar search to those I had done previously, I looked for events where the number of threads created exceeded 2 standard deviations:

![Splunk101](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/99cfb066-4e1f-4633-899e-5e5b7f3ea252)

The steps of this search were to:

Bin the events into 1 hour bins
Count the number of threads created based on the source and target images
Calculate the average and standard deviation of the number of threads created
Find all instances where the number of threads created was greater than 2 standard deviations

This resulted in finding the malicious file **randomfile.exe** created multiple threads in notepad.exe.

## Finding the Source of the Intrusion

Throughout the previous sections I have been investigating different parts of an attack chain that started with domain credentials being dumped which resulted in host infections and data exfiltration. There have been a number of related malicious processes, commands, and DLLS, most notably notepad.exe and rundll32.exe.

In this section I want to learn more about this attack and find its original method of intrusion.

### Find the process that created remote threads in rundll32.exe

Finding this process was simple because doing a search on event code 8 events where the target image was rundll32.exe only resulted in one program, **randomfile.exe**:

![Splunk102](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/89c26344-ae38-4ee4-af79-8ba277caa418)

### Find the process that started the infection

My initial thoughts on how to further investigate the start of the infection was to combine the previous findings about **randomfile.exe** with the known C2 servers that I found earlier:

![Splunk103](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/9f02445d-2ebb-4ad7-a4ee-b0327fe48576)

Looking into the events that this search provided reminded me of the infected users that could lead to how this infection started:

![Splunk104](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/3855cdc4-6651-4856-8ea7-08b1fd9bcc44)

Since the **waldo** user has been prevalent throughout this project I decided to look into the types of events that are related to this account and the C2 servers.

Interestingly, I found many events related to Sysmon event code 15 which is related to external downloads from the web:

![Splunk105](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/5c373bf1-9617-4746-aa8a-f3fd739d01a3)

I wanted to focus on these event code 15 events so I started by first getting an idea of the processes that might be related to these events:

![Splunk106](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/9784ad40-4978-4367-b70e-50553e72cba6)

Lots of these programs appear to be malicious based on the prior knowledge of the attack and the only one that I haven't seen before is demon.exe. Luckily this list is very small so I can now begin thinking in terms of a timeline.

I do a simple search to see all of the events related to the waldo user and the C2 servers, but I make sure to see the very first events that have occurred:

![Splunk107](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/45774087-45a3-487b-bdd8-77bea5a153ca)

From this search I can see that on 10/5/22 the first occurrence of contact with the C2 servers was an event code 15 event categorized as a "Drive-by Compromise" related to the **Run.dll** file in the user waldo's downloads folder:

![Splunk108](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/a0a953bb-8006-452f-a8a0-596d66d1f135)

A DLL file in the downloads folder itself is suspicious and along with the fact that there is no legitimate DLL named "Run.dll" it's safe to assume this is a malicious file worth investigating.

In this search I also inspected the different target file names and saw some of the usual suspects:

![Splunk109](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/1688abb0-7966-4e63-b078-acfdd652c5ce)

Since the Run.dll events seemed to happen before the demon.dll files, I did a quick search on it:

![Splunk110](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/9838508c-2999-4a13-ae1e-48e18c8f9875)
![Splunk111](https://github.com/most-e/Understanding-Log-Sources-Investigating-with-Splunk/assets/156223367/1189928d-45da-443c-9571-d3bc86d8ef3b)

By looking at the first ever event that occurred with Run.dll I can see that **rundll32.exe** was used to load it (Sysmon event code 7) only 8 minutes after the Run.dll file was detected as a potential drive-by compromise.

With this knowledge, I can conclude that the waldo user downloaded the malicious file Run.dll which then exploited rundll32.exe to initiate the attack.



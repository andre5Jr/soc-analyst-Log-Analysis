📝 Project Title:

TryHackMe – Snort Challenge: Live Attacks – Scenario 1 | Brute Force

🎯 Objective:

Analyze live network traffic to detect, stop, and document a brute-force attack using Snort in both sniffer and IPS modes.

🛠️ Tools Used:

Snort (Sniffer & IPS modes)
Linux Terminal

❌ Skills Demonstrated:

Network traffic inspection
Snort rule writing (detection & prevention)
Real-time threat mitigation
Service and protocol identification

1. Project Overview
This project focused on using Snort to detect and stop a live brute-force attack in a simulated environment. After analyzing captured traffic, I created and tested a custom IPS rule to block the attack. The success of the mitigation was confirmed when a flag appeared on the desktop. The investigation also required identifying the targeted service and the protocol/port involved.

2. Task Breakdown
✏️ Task 1: Stop the Attack and Retrieve the Flag

⭕️ Objective:
Detect and block the brute-force attack using Snort to trigger the appearance of the flag.

⭕️ Method:

Ran Snort in sniffer mode (-A console) to identify suspicious activity

Analyzed repeated login attempts to detect brute-force behavior

Wrote a custom Snort rule to block SSH login attempts

Ran Snort in IPS mode (-A full) to enforce the rule and stop the traffic

✅ Outcome:
Attack was successfully blocked. After blocking traffic for over one minute, the flag appeared on the desktop.

📸 Screenshot Space:
[Snort output, rule file, or flag confirmation]

✏️ Task 2: Identify the Targeted Service

⭕️ Objective:
Determine which service was being attacked in the brute-force attempt.

⭕️ Method:

Inspected packet payloads and destination ports

Recognized patterns consistent with SSH authentication attempts

✅ Outcome:
Identified SSH as the targeted service.

📸 Screenshot Space:
[Capture of traffic showing SSH activity or port 22]

✏️ Task 3: Identify the Protocol and Port Used

⭕️ Objective:
Find the protocol and port associated with the brute-force traffic.

⭕️ Method:

Analyzed Snort logs and packet headers

Identified protocol and port information from traffic metadata

✅ Outcome:
Determined the attack used TCP protocol on port 22.

📸 Screenshot Space:
[Network trace or Snort log showing TCP:22]

3. Analysis and Reflection
💡 Challenges Faced:

Writing an accurate rule that targets brute-force patterns without false positives

Understanding Snort log verbosity and output modes

💡 Lessons Learned:

Snort requires precise rule syntax to function effectively in IPS mode

Detecting brute-force attempts involves analyzing traffic behavior, not just content

Live traffic inspection teaches rapid incident response

💡 Relevance to SOC Analyst Role:

Reinforces familiarity with IDS/IPS workflows

Demonstrates ability to identify threats and take immediate mitigation action

Builds practical rule-writing and traffic analysis skills

💡 Relevance to Penetration Testing:

Helps understand how defenders detect common attacks

Encourages more creative and evasive attack simulations

Informs how to test and improve security controls

4. Conclusion
💡 Summary:
Used Snort to detect and stop a brute-force SSH attack. Created a custom rule to block malicious traffic, resulting in a retrieved flag. Documented the protocol, port, and service involved.

💡 Skills Gained:
Snort configuration and rule creation
Live network traffic analysis
Service and protocol identification
Defensive response validation

💡 Next Steps:
Explore advanced detection (e.g., port scans, DDoS)
Integrate Snort with alerting tools (e.g., Splunk, ELK)
Automate rule deployment for faster response

![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/8d3da9a81c7266e371a01ae795d4c346fde059af/Scenario%201-1.png) 
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-2.png) 
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-3.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-4.png)     
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-5.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Task%203%20-%20Identify%20the%20Protocol%20and%20Port%20Used.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-7.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Task%202%20-%20Identify%20the%20Targeted%20Service.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-9.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-10.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-11.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-12.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-13.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-14.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-15.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-16.png)   
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Scenario%201-17.png)  
![image alt](https://github.com/andre5Jr/soc-analyst-Log-Analysis/blob/e83f912cf2f6d5c8c2eeded0fe721b30249ea291/Task%201%20-%20Stop%20the%20Attack%20and%20Retrieve%20the%20Flag.png) 

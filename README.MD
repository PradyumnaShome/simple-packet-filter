# Simple Packet Filter Firewall

I am not very sure which team is my top choice - I would pick `Data` because of my interest in recommender systems, inference engines, and machine learning / natural language processing, and `Platform` because I get to work with infrastructure, cloud deployments, and DevOps in general.

For the packet filter, I used an IntervalTree, that keeps track of ranges of IP Addresses, within a range, I store the other 3 details for matching. This lets me perform range queries efficiently (since the IP Address space is huge) without using too much storage. I could probably have added another IntervalTree for each IP address interval, to make the port selection even more efficient.

## Testing
I considered some test cases that can be found in `test_simple.py`. 
First, run `pip install -r requirements.txt`.
Tests can be run by running `pytest` in the project directory .

These are the following situations I tested:
- IP address specified is at the beginning / end of the range (first / last possible accepted value)
- Everything matching except the direction, or protocol
- Everything matching but wrong port

I could have made more complex tests, involving overlapping rules, but was unsure what the right output was under those constraints, and felt it was something I would have more strongly considered if I had more time.
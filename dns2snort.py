#!/usr/bin/python
# Version 1.0
##Imports##
#Argparse for fancy cli args
#textwrap for a fancy help/description output

import argparse
import textwrap
import re

#Initialize argparse and print the big ass description and help usage block if -h or --help is used

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent('''
                    dns2snort.py
                Brought to you by:
                    @da_667
                With Special Thanks from:
                    @botnet_hunter
                     @3XPlo1T2
                ---------------------
Generates DNS snort rules from a list of domains.
Usage: dns2rule.py -i <infile> -o <outfile> -s 1000000
Infile format:
www.evil.com
Outfile format:
alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"BLACKLIST DNS known malware domain www.evil.com"; flow:to_server; byte_test:1,!&,0xF8,2; content:"|03|www|04|evil|03|com|00|"; fast_pattern:only; metadata:service dns;  sid:1000000; rev:1;)
'''))

#Infile, outfile, and sid arguments via ArgParse are all required.

parser.add_argument(
    '-i',
    dest="infile",
    required=True,
    help=
    "The name of the file containing a list of Domains, One domain per line.")

parser.add_argument('-o',
                    dest="outfile",
                    required=True,
                    help="The name of the file to output your snort rules to.")

parser.add_argument(
    '-s',
    dest="sid",
    type=int,
    required=True,
    help=
    "The snort sid to start numbering incrementally at. This number should be between 1000000 and 2000000.")

parser.add_argument(
    '-w',
    dest="www",
    required=False,
    action='store_true',
    help="Remove the 'www' subdomain from domains that have it.")

args = parser.parse_args()

#This is a small check to ensure -s is set to a valid value between one and two million - the local rules range.

if args.sid < 1000000:
    print "The Value for sid (-s) is less than 1000000. Valid sid range is 1000000 to 2000000 (one million to two million)"
    exit()
elif args.sid > 2000000:
    print "The Value for sid (-s) is greater than 2000000. Valid sid range is 1000000 to 2000000 (one million to two million)"
    exit()

#fout is the file we will be outputting our rules to.
#f is the file we will read a list of domains from.
#This script iterates through each line (via for line loop) and splits on periods (.), creating a list for each line.
#The script calculates the segments of the domain in question (can handle 1-4 segments -- e.g. .ru (1 segments, TLD) all the way to this.is.evil.ru (4 segments))
#Each segment of a domain has it's string length calculated and converted to hex.
#If the segment is less than or equal to 0xf, this is converted to "0f" (padded with a zero, since snort rules expect this)
#The hexidecmal letter is converted to upper case, and the rule is written to a file.
#after the rule is written the SID number is incremented by 1 for the next rule.

with open(args.outfile, 'w') as fout:
    with open(args.infile, 'r') as f:
        for line in f:

            domain = line.rstrip()

            if args.www == True:
                domain = re.sub('^www\.', '', domain, flags=re.IGNORECASE)
            segments = domain.split('.')

            #try/except fixes a bug with TLD rule creation where segment has 2 elements and element 0 is '' for some reason.

            try:
                segments.remove('')
            except ValueError:
                pass

            i = 0
            rulefragment = ""

            for segment in segments:
                seghex = (hex(len(segments[i])))[2:]
                if int(len(seghex)) == 1:
                    seghex = "0%s" % seghex
                rulefragment += seghex.upper() + "|" + segment + "|"
                i += 1

            rule = (
                "alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:\"BLACKLIST DNS domain %s\"; flow:to_server; byte_test:1,!&,0xF8,2; content:\"|%s00|\"; fast_pattern:only; metadata:service dns;  sid:%s; rev:1;)\n"
                % (domain, rulefragment, args.sid))

            fout.write(rule)
            print rule

            args.sid += 1
exit()

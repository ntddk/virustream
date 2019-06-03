#!/usr/bin/env python
#coding: utf-8

import argparse
import re
import keys
import requests
import sys
from tqdm import tqdm
from tweepy import *
from pymisp import PyMISP
from regex import *
from keys import *

def feed(txt):
    with open(txt, 'r') as l:
        lines = l.readlines()
    l.close()
    return lines

def get_oauth():
    auth = OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_key, access_secret)
    return auth

def check_hash(tweet):
    hash_dict = {}

    # Regex search
    sha256s = sha256_pattern.findall(tweet)
    sha1s = sha1_pattern.findall(tweet)
    md5s = md5_pattern.findall(tweet)

    if sha256s:
        for sha256 in sha256s:
            hash_dict.update({sha256: 'sha256'})
    elif sha1s:
        for sha1 in sha1s:
            hash_dict.update({sha1: 'sha1'})
    elif md5s:
        for md5 in md5s:
            hash_dict.update({md5: 'md5'})

    return hash_dict

def submit_to_slack(tweet_url):
    payload = {
        'channel': slack_channel,
        'username': slack_username,
        'text': tweet_url
    }
    url = slack_url
    payloadJson = json.dumps(payload)
    requests.post(url, data=payloadJson)

def submit_to_misp(hash_dict, tweet, tweet_url):
    misp = PyMISP(misp_url, misp_key, True, 'json')

    event_name = 'New tweet from ' + status.author.screen_name
    comment = tweet + '\t' + tweet_url

    for malware_hash in hash_dict:
        if event == 0:
            event = misp.new_event(0, 4, 0, event_name)
            eventid = event['Event']['id']

        hash_type = hash_dict[malware_hash]
        if hash_type == 'sha256':
            misp.add_hashes(event, sha256=malware_hash, comment=comment)
        elif hash_type == 'sha1':
            misp.add_hashes(event, sha1=malware_hash, comment=comment)
        elif hash_type == 'md5':
            misp.add_hashes(event, md5=malware_hash, comment=comment)

def download(hash_dict):
    for malware_hash in hash_dict:
        params = {'apikey': vt_key, 'hash': malware_hash}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/download',
                    params=params, stream=True)

        with open(malware_hash, 'wb') as f:
            for data in tqdm(response.iter_content()):
                f.write(data)
        f.close()

class StreamListener(StreamListener):
    def on_status(self, status):
        tweet = str(status.text.encode('utf-8'))
        tweet_url = 'https://twitter.com/' + status.author.screen_name + '/status/' + status.id_str

        # Replacement
        tweet = tweet.replace('hxxp', 'http')
        tweet = tweet.replace('[.]', '.')
        tweet = tweet.replace('\\n', ' ')
        tweet = tweet.replace('b\'', '')
        tweet = tweet.replace('b\"', '')
        tweet = tweet.replace('\'', '')
        tweet = tweet.replace('\"', '')
        tweet = tweet.replace('\\', '/')

        # Ignore retweets
        if 'RT' in tweet[:2]:
            return

        # Ignore reply
        try:
            if status.in_reply_to_status_id:
                return
        except:
            pass

        # Extract URLs
        try:
            for url in status.entities['urls']:
                if re.search(url['url'], tweet):
                    tweet = re.sub(url['url'], url['expanded_url'], tweet)
        except:
            pass

        # Check hash
        hash_dict = check_hash(tweet)

        # Slack
        if len(slack_url) > 0:
            submit_to_slack(tweet_url)

        # MISP
        if len(misp_key) > 0:
            submit_to_misp(hash_dict, tweet_url)

        # VirusTotal
        if len(vt_key) > 0:
            download(hash_dict)

    def on_error(self, status_code):
        if status_code == 420:
            return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('analysts', help='list_of_malware_analysts')
    args = parser.parse_args()

    analysts = list(filter(lambda x:x.replace('\n', ''), feed(args.analysts)))

    auth = get_oauth()
    stream = Stream(auth, StreamListener(), secure=True)
    stream.filter(track=analysts, is_async=True)

if __name__ == '__main__':
    main()


#!usr/bin/bash python

### WebBEAT checker
### Building a DB of sites living attributes
### Created by Zdenko Vozar
### v.0.3 2022 09 04

import requests
from bs4 import BeautifulSoup
import json
from datetime import datetime
import time
from time import sleep
import whois
from whois.parser import WhoisEntry
import re
import argparse

### Requirements.txt
#argparse>=1.4.0
#bs4>=4.11.1
#html5lib>=1.1
#python-whois>=0.8.0
#requests>=2.23.0
#requests-oauthlib>=1.3.1

def get_time():
  d= datetime.now()
  return str(d.strftime("%Y-%m-%d %H:%M:%S")) # %Z

def transf_time(d):
  if  isinstance(d, list):
    return [transf_time(item) for item in d]
  else:
    if len(d) == 10:
      return str(datetime.strptime(d,'%d.%m.%Y'))
    else:
      if len(d) == 19:
        return str(datetime.strptime(d,'%d.%m.%Y %H:%M:%S'))
      else:
        print('str',d)
        return str(d.strftime("%Y-%m-%d %H:%M:%S")) # %Z

def get_NER(ret, re_type):
    mail  = r'([A-z, 0-9, \-, \., \_]*.\@[A-z, 0-9, \-, \., \_]*.\.[A-z]{1,20})'
    name  = r'(([A-Z][a-z]*.){2,5})'
    ip    = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
    brack_n= r'\(([a-z].*)\)'
    date = r'((registered\: *)([0-9]{2}.[0-9]{2}.[0-9]{4}))' # and match + groups (for WHOIS)
    if re_type == 'name':
      p= re.compile(name)
    else:
      if re_type == 'mail':
        p=re.compile(mail)
      else:
        if re_type == 'ip':
          p=re.compile(ip)
    #print('get_NER ' + re_type + ' : ', p.findall(ret))
    if p.findall(ret):
      if re_type == 'ip':
        return p.findall(ret)[0].strip(' ,;)')
      if re_type == 'date':
        return p.findall(ret)[0][2]
      return [item.strip(' ,;') if re_type == 'mail' else item[0].strip(' ,;')  for item in p.findall(ret)]
    else:
      return ['None']

def connection_data(seed, connection, peer_ip, peer_port, headers):
    """ Creating connection dataobject
    """
    record_conn_data = {'seed': seed,'redirect_depth': str(len(connection.history)),#redirect = seed  #'connection_test':connection.headers,
                        #'connection_history': str(connection.history), 
                        'redirect': connection.url, #redirect_last
                        'peer':{'peer_ip':str(peer_ip), 'peer_port':str(peer_port)}, 'Server':{},
                        'code': str(connection.status_code),'status': connection.reason} #,'Content-Type': '', 'Encoding': '', 'Length': 0,'x-cache': '','x-cache-lookup': '','Date':''} 

    if record_conn_data['redirect_depth'] == '0':
         record_conn_data['redirect_depth'] = '-1'
    print("Connection headers", connection.headers)
    record_conn_data['Error']= ['0', '']
    if peer_port=='None':
        record_conn_data['peer']['peer_port']='0'
    for header in headers_out:
        try:
          if header == 'Content-Type':
              content_t = connection.headers[header].split(';')
              record_conn_data['Content-Type'] = content_t[0]
              record_conn_data['Encoding'] = content_t[1].strip()
          else:
            if header == 'Date':
              server_time = connection.headers['Date']
              result_date =  datetime.strptime(server_time, '%a, %d %b %Y %H:%M:%S %Z')
                                               #'Wed Mar 16 16:12:05 2016'
                                               #'Wed, 09 Mar 2022 12:05:47 GMT'
              #print('Result date:', result_date.strftime("%Y-%m-%d %H:%M:%S %Z"))
              record_conn_data['Date'] = result_date.strftime('%Y-%m-%d %H:%M:%S') # %Z             
            else:
              if header == 'Server':
                print(' -- Connection Server test: ', str(connection.headers[header]))
                if "/" in connection.headers[header]:
                  srv = connection.headers[header].lower()
                  srv= srv.split('/')
                  #record_conn_data[header] = {'server-engine': srv[0], 'server-version': srv[1]}
                  record_conn_data['Server']['server-engine'] =  str(srv[0])
                  record_conn_data['Server']['server-version'] =  str(srv[1])
                else:
                  #record_conn_data[header] = {'server-engine': srv, 'server-version': 'NA'}
                  record_conn_data['Server']['server-engine'] =  str(srv)
                  record_conn_data['Server']['server-version'] =  'NA'
              else:
                  record_conn_data[header] =str(connection.headers[header])
        except:
          record_conn_data['Error']= [str(int(record_conn_data['Error'][0]) +1), record_conn_data['Error'][1] + header + '; ']
          if header == 'Content-Length':
              record_conn_data['Content-Length']='-1'
          if header == 'Server':
              record_conn_data['Server']['server-engine'] =  'NA'
              record_conn_data['Server']['server-version'] =  'NA'
    print("Connection data", record_conn_data)
    return [record_conn_data]

def soup_attrs_content(soup, tag, attr_name, attr_val, attr_target):
      content = []
      if soup.find_all(tag,attrs={attr_name : attr_val}):
        met_desript= soup.find_all(tag, attrs={attr_name : attr_val})
        for item in met_desript:
          content.append(item[attr_target])
      else:
         content.append('None')
      return content

def metadata_extraction(content, code, leng, charset):
    """Creating metadata object
    """
    h1_titles, h2_titles,  met_description, met_keywords, met_author = [],[],{},{},{}
    met_author['mails'], met_author['names'], met_keywords['keys'] = [],[],[]

    #print("Content", content)
    print("Metadata extraction", code, leng,  charset)
    if code == '200':
      soup = BeautifulSoup(content, 'html5lib')
      #print(soup)
      for item in soup.find_all('h1'):
          h1_titles.append(item.text.replace('\n','').strip())
      for item in soup.find_all('h2'):
          h2_titles.append(item.text.replace('\n','').strip())
      if soup.find('title'):
          title = soup.find('title').text
      else:
          title = 'None'
      met_description=soup_attrs_content(soup, 'meta','name','description','content')
      met_keywords['str']=soup_attrs_content(soup, 'meta','name','keywords','content') # rozpadnout na list dle carek / mezer
      met_author['str']=soup_attrs_content(soup, 'meta','name','author','content') #extrakce emailu
      for item in met_author['str']:
        if item != "None":
          met_author['mails'].extend(get_NER(item, 'mail'))
          met_author['names'].extend(get_NER(item, 'name'))
      for item in met_keywords['str']:
        if item != "None" and ';' in item:
          met_keywords['keys'].extend(item.split(';'))
        if item != "None" and ',' in item:
          met_keywords['keys'].extend(item.split(','))
    else:
      title = 'None'
      met_description = ['None']
      met_keywords = ['None']
      if int(leng) > 20:
        soup = BeautifulSoup(content, 'html5lib')
        for item in soup.find_all('h2'):
            h2_titles.append(item.text.replace('\n','').strip())
    record_data = [{'crawler': 'WebBeat ' + str(WebBEAT_v), 'timestamp': get_time(), 'title': title, 'h1_titles': h1_titles, 'h2_titles': h2_titles,  'met_description':met_description, 'met_keywords':met_keywords, 'met_author':met_author }]
    return record_data

def get_whois(seed, record):
    global whois_time
    w, times, domain_data, persons = {}, {}, {}, []
    w['Error']= [1, '']

    print('\n -- Working on WHOIS; ',get_time())

    try:
      whois_domain = seed
      for prefix in ['https://','http://','www.']:
          if prefix in seed:
            #whois_domain = whois_domain.removeprefix(prefix)
            whois_domain = remove_prefix(whois_domain, prefix)
      whois_domain = whois_domain.split('/', 1)[0]
      print('  -- firing whois on: ', whois_domain)
      w = whois.whois(whois_domain)
      print('  -- whois response received')

      print(w['domain_data'])
      for i, item in enumerate(['registrar_dom_act','registered_dom_act', 'changed_dom_last', 'expire_dom_last']):
        if item in ['registered_dom_act', 'changed_dom_last','expire_dom_last']:
          domain_data[item] = transf_time(w['domain_data'][i])
        else:
          domain_data[item] = w['domain_data'][i]
      del w['domain_data']
      del w['registered_date']
      del w['expiration_date']
      domain_data['registrant_dom']= w['registrant_domain']
      del w['registrant_domain']
      #print("DD:", domain_data)

      if len(w['contact_data_pers']) % 3 == 0:
        x = len(w['contact_data_pers'])
        for i in range(0,int(x/3)):
          y= range(i*3-1,i*3+2)
          #print(i, y)
          tmp = {'id':w['contact_data_pers'][y[0]],'pers_name':w['contact_data_pers'][y[1]], 'registrar':w['contact_data_pers'][y[2]]}
          persons.append(tmp)
      else:
         persons.append({'mess':w['contact_data_pers']})
      del w['contact_data_pers']
      print(persons)

      person_tmp, person_org=[],[]
      po,dr=False, False
      for item in w['contact_data_org']:
        if (item in w['admin_contacts'] or item in w['tech_contacts']) and item not in domain_data['registrant_dom']:
            if po:
              person_org.append(person_tmp)
            dr=False
            po=True
            person_tmp=[]
            person_tmp.append(item)
        else:
            if po:
              person_tmp.append(item)
            else:
              if dr:
                domain_data['registrant_dom_adress'].append(item)
              else:
                if item in domain_data['registrant_dom']:
                  if po:
                    person_org.append(person_tmp)
                    person_tmp=[]
                  dr = True
                  po = False
                  domain_data['registrant_dom_adress']=[]
                  domain_data['registrant_dom_adress'].append(item)
      if po and person_tmp:
        person_org.append(person_tmp)
      del w['contact_data_org']


      w['Error']= ['0', '']
      record['whois'] = [w]
      record['whois'][0]['whois_domain'] = whois_domain
      #record['whois']['times'] = times
      record['whois'][0]['domain_data'] = domain_data
      record['whois'][0]['persons'] = persons
      record['whois'][0]['persons_org'] = person_org
      ns = []
      i = 1
      if len(record['whois'][0]['name_servers']) > 0:
        for nss in record['whois'][0]['name_servers']:
            if " (" in nss:
              nss_tmp = nss.split(' (')
              #print('NSS TMP:', nss_tmp)
              ns.append({'n_srv':i, 'srv': nss_tmp[0], 'srv_ip': get_NER(nss_tmp[1],'ip')})
            else:
              ns.append({'n_srv':i, 'srv': nss_tmp[0], 'srv_ip':'None'})
            i+=1

      record['whois'][0]['name_servers'] = ns
      #print("OK", record)
      return record
    except whois.Exception as err: #PywhoisError
      print(err)
      if '% No entries found' or 'no entries found' in str(err):
          w['Error']=['-101', ' No entries found.']
      if 'Your connection limit exceeded' in str(err):
          w['Error']=['1', ' Connection limit exceeded.']
          sleep(31)
          whois_time = whois_time +30
          w = get_whois(seed, record)
      print('   -- whois problem rec', w)
      record['whois'] = [w]
      return record

#until python 3.9
def remove_prefix(input_string, prefix):
    if prefix and input_string.startswith(prefix):
        return input_string[len(prefix):]
    return input_string

def get_data(endpoint_seedsin):
    ret = requests.get(endpoint_seedsin, allow_redirects=True,  timeout=(2,30), stream=True) #  headers=headers_in,, timeout=0.001/timeout_margin, , allow_redirects=True
    datad = json.loads(ret.content)
    print('  -- Data grabbed')
    seeds = []
    for seed in datad['data']:
        seeds.append('https://' + seed['url'])
    print('  -- Total count of seeds: ', len(seeds))

    seedsconc = ' '.join(seeds)
    return seedsconc

def send_to_DB(endpoint, data ):
  # 'http://10.5.1.78/api/import/'
   print('\n -- Importing to DB; ',get_time())
   headers = {"Content-Type": "application/json"}

   print_data = json.dumps(data, indent = 4, ensure_ascii=True)
   print(' --- Records:\n', print_data)
   post_data = json.dumps(data, ensure_ascii=True)
   #r = requests.post(endpoint, headers=headers, json = post_data) # json makes json.dumps, but without parameters
   r = requests.post(endpoint, headers=headers, data = post_data)
   print(f"Status Code: {r.status_code}")
   print(r.text)
   #resp_DB = json.loads(r.text)
   #print(resp_DB)
   #print(f"Status Text: {resp_DB['stats']}")

def work_on_seeds(endpoint, seeds, whois_c, pause_c, user_agent, headers_in, headers_out, timeout_margin, max_redirects):
    """
            ## Datatype
            #['https://mzk.cz/', 1, 200, 'OK', 'text/html', 'charset=utf-8', '18210', 'Apache/2.4.25 (Debian)', None, 'Wed, 09 Mar 2022 14:02:56 GMT', None, None, None]
            #record_data = {'h1_titles':[], 'h2_titles':[],  'met_description':'', 'met_keywords':'' }
            #record = {'UUID': seed,'harvest_metadata':record_harv_met, 'connection_metadata':record_conn_data, 'page_data':record_data }
    """
    global whois_time
    #record_json = []
    whois_time = pause_c
    for i, seed in enumerate(seeds):
        sleep(whois_time)
        print('\n Working on n. ',i, ' seed: ', seed, get_time())
      ## Datatype
        record_seeds_report= {'code': '0','status': '','seed': seed,'redirect': '','redirect_depth': '-1'}
        #record_conn_data = [{'seed': seed,'redirect_depth': 0, 'code': 0,'status': '','Content-Type': '', 'Encoding': '', 'Length': 0,'x-cache': '','x-cache-lookup': '','Date':''}] 
        record_conn_data = {'redirect': seed,'redirect_depth': '-1', 'code': '0','status': '','Content-Type': '', 'Encoding': '', 'Length': '0','x-cache': '','x-cache-lookup': '','Date':''}
        record = {'url': seed,'harvest_metadata': [{'crawler': 'WebBeat ' + str(WebBEAT_v), 'timestamp': get_time(),'seeds_report': record_conn_data}]}


      ## WHOIS
        if whois_c:
          record = get_whois(seed, record)
          sleep(3)
        ##print("WHOIS Record", record) 

      ## Requests
        response, connection, metadata, data = [], [], [], []
        try:
          print('\n -- Working on Live requests; ',get_time())
          ret = requests.get(seed, headers=headers_in, allow_redirects=True,  timeout=(2,30), stream=True) # , timeout=0.001/timeout_margin, , allow_redirects=True
          if ret.encoding is None:
            ret.encoding = 'utf-8'
          try:
            peer_ip, peer_port = ret.raw._connection.sock.getpeername()
          except:
            peer_ip, peer_port = 'None','None'
        except requests.exceptions.Timeout as err:
            print("Timeout: {0}".format(err))
            # Maybe set up for a retry, or continue in a retry loop
            post_json = record
            send_to_DB(endpoint, post_json)
        except requests.exceptions.TooManyRedirects as err:
            print("TooManyRedirects: {0}".format(err))
            # Tell the user their URL was bad and try a different one
            post_json = record
            send_to_DB(endpoint, post_json)
        except requests.exceptions.RequestException as err:
            print("RequestException: {0}".format(err))
            err = str(err)
            print(err)
            if '[Errno -2]' in err:
            err = str(err)
            print(err)
            if '[Errno -2]' in err:
                record['harvest_metadata'][0]['seeds_report']=[{}]
                record['harvest_metadata'][0]['seeds_report'][0]['Error']=['1', 'RequestException :: ' + 'Failed to establish a new connection: [Errno -2] Name or service not known']
                record['harvest_metadata'][0]['seeds_report'][0]['code']='-2'
                post_json = record
                send_to_DB(endpoint, post_json)  # catastrophic error. bail.                #raise SystemExit(e)          try:
        try:
          try:
            record['harvest_metadata'][0]['seeds_report']= connection_data(seed, ret, peer_ip, peer_port, headers=headers_in)
          except:
            record['harvest_metadata']=[{'crawler': 'WebBeat ' + str(WebBEAT_v), 'timestamp': get_time(),'Error':'Not extracted'}]
          if record['harvest_metadata'][0]['seeds_report'][0]['code'] == '200':
              try:
                record['page_data'] = metadata_extraction(ret.content,  record['harvest_metadata'][0]['seeds_report'][0]['code'], record['harvest_metadata'][0]['seeds_report'][0]['redirect_depth'], record['harvest_metadata'][0]['seeds_report'][0]['Encoding'])
              except:
                  record['page_data']=[{'crawler': 'WebBeat ' + str(WebBEAT_v), 'timestamp': get_time(),'Error':'Not extracted'}]
          post_json = record
          send_to_DB(endpoint, post_json)
        except:
          print("Extraction runtime exception")
          post_json = record
          send_to_DB(endpoint, post_json)

## Monkey patching

#from whois.parser import WhoisEntry  #see above

class WhoisCz(WhoisEntry):
    """Whois parser for .cz domains
    """
    regex = {
        'domain_name':              r'domain: *(.+)',
        'domain_data':              r'registrar: (.+)\nregistered: (.+)\nchanged: *(.+)\nexpire: *(.+)',
        'contact_data_org':         r'contact: *(.+)\norg: *(.+)\nname: *(.+)\naddress: *(.+)\naddress: *(.+)\naddress: *(.+)\naddress: *(.+)',
        'contact_data_pers':        r'contact: *(.+)\nname: *(.+)\nregistrar: *(.+)',
        'registrant_domain':        r'domain: .+\nregistrant: *(.+)',
        'registrars':               r'registrar: *(.+)',
        'name_servers':             r'nserver: *(.+)',
        'admin_contacts':           r'admin-c: *(.+)',
        'tech_contacts':            r'tech-c: *(.+)',
        #'registered_date':          r'registered: *(.+)',
        #'expiration_date':          r'expire: *(.+)',
        #'registrant_name':          r'registrant: *(.+)',
        #'registrant_name_contact':  r'name: *(.+){2,4}',
        #'registrant_org':           r'org: *(.+){1}',
        #'registrant_street':        r'adress: *(.+){5}',
        #'registrant_city':          r'adress: *(.+){6}',
        #'registrant_zipcode':       r'adress: *(.+){7}',
        #'country':                  r'adress: *(.+){8}',
        #'updated_date':             r'changed: *(.+)',
        # created, changed regitrar
    }


    def __init__(self, domain, text):
          if '% No entries found.' in text or 'Your connection limit exceeded' in text:
              #raise #PywhoisError
              raise Exception(text)
          else:
              #print(text)
              WhoisEntry.__init__(self, domain, text, self.regex)

if __name__=="__main__":

  ###  SET UP #

  ## Set up class customizations
  whois.parser.WhoisCz = WhoisCz

  ## Proprietary variables
  WebBEAT_v = 0.3
  user_agent='Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5'
  headers_in = {'user-agent': user_agent}
  headers_out=['Content-Type','Content-Length','Server','age','Date','x-cache','x-cache-lookup','X-Powered-By']

  ## Set up parser
  parser = argparse.ArgumentParser()
  parser.add_argument("-e", "--Endpoint", help = "set API DB endpoint; -e {endpoint adress}/api/v2")
  parser.add_argument("-s", "--Seeds", help = "set API seeds list; -s \'https://webarchiv.cz https://nkp.cz\' OR dont specify and get it from seeds endpoint")
  #parser.add_argument("-w", "--WHOIS", help = "activate WHOIS checking procedure, def. deactivated; -w True")
  parser.add_argument("-p", "--Pause", action='store', help = "set Pause between seeds, def. for Whois 61 s.; -p 10")
  parser.add_argument("-t", "--TimeoutMargin", help = "set Timeout Margin call constraint in live requests, def. 0.02;")
  parser.add_argument("-r", "--MaxRedirects", help = "set Max Redirects constraint in live requests, def. 12;")
#  parser.add_argument("-o", "--Output", help = "show Output;")
  parser.add_argument('--whois_c', action='store_true', help = "Activate WHOIS checking procedure, def. activated. Use as parameter; --whois_c")
  parser.add_argument('--no-whois', dest='whois_c', action='store_false', help = "Desactivate WHOIS checking procedure, def. activated. Use as parameter; --no-whois")
  parser.set_defaults(whois_c=True, pause_c= 61)
  args = parser.parse_args()

  ## Parse input variables
#  if args.Output:
#    print("Displaying Output as: % s" % args.Output)
  if args.Endpoint:
    endpoint = str(args.Endpoint)
  else:
    endpoint = 'https://121.0.0.1/api/v2/' #?db=test'
  if args.Seeds:
    seeds = args.Seeds.split(' ')
  else:
    endpoint_seedsin =  endpoint + '?type=url'
    seeds = get_data(endpoint_seedsin)
    seeds = seeds.split(' ')
  if args.Pause:
    pause_c=int(args.Pause)
  else:
    pause_c=61
  if args.whois_c:
    whois_c=args.whois_c
  else:
    #print('WH False') normalize conditional args
    whois_c=False
  if args.MaxRedirects and type(args.MaxRedirects) == int:
    max_redirects= args.MaxRedirects
  else:
    max_redirects = 15
  if args.TimeoutMargin and args.TimeoutMargin.isdecimal():
    timeout_margin = args.TimeoutMargin
  else:
    timeout_margin = 0.02




  ### RUN  ###
  print('>> WebBEAT <<\n\nVersion:\n -- ', WebBEAT_v)

  print('\nVariables:')
  print(' -- pause constraint: ', pause_c)
  print(' -- Whois module: ', whois_c)
  print(' -- live requests maximum redirects: ', max_redirects)
  print(' -- live requests timeout: ', timeout_margin)
  print('\nSeeds:')
  [print(' --', seed) for seed in seeds]
  print('\nProgramme run:\n')
  work_on_seeds(endpoint, seeds, whois_c, pause_c, user_agent, headers_in, headers_out, timeout_margin, max_redirects)

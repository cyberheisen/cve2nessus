import csv
import requests
import os
import sys
import time
from bs4 import BeautifulSoup

# This is the base url used for the plugin query
BASEURL = "https://www.tenable.com/plugins/search?q="

# your basic run of the mill file read function
def readfile(filename):
    f = open(filename,"r")
    lines = f.readlines()
    return lines

# This is where we query the Tenable website and parse the return data
def searchForPlugin(CVE):
    plugins = []
    plugin = {}
    # Adding the CVE number to the base url query.  Note the %22 url encoded quotes is required
    url = BASEURL + "%22" + CVE + "%22"
    print ("Searching for: %s" % CVE) 
    # Making the web request
    r = requests.get(url)
    # Parsing the response using Beautiful soup
    page = BeautifulSoup(r.content, 'html.parser')
    # We're only interested in the "results-table" element
    table = page.find('table', {'class' : 'results-table table'})
    # if results-table exists, we will interate through the rows and then the columns. A CVE may have multiple 
    # Nessus plugins.  One plugin is listed per .
    if table:
        rows = table.findAll(lambda tag: tag.name=='tr')
        for row in rows:
            cols = row.find_all('td')
            # for each row, save the column into our plugin dictionary object.
            if cols:
                plugin['cve'] = CVE
                plugin_id = cols[0].a.contents[0]
                plugin['plugin_id'] = plugin_id
                plugin['plugin_name'] = cols[1].contents[0]
                plugin['product'] = cols[2].contents[0]
                plugin['family'] = cols[3].a.contents[0]
                plugin['published'] = cols[4].contents[0]
                plugin['updated'] = cols[5].contents[0]
                plugin['severity'] = cols[6].span.contents[0]
                plugins.append(plugin)
                print("\t %s" % plugin_id)
    else:
        # If there are no rows returned, there isn't a plugin available.
        print("No Nessus plugins found")
    return plugins

# This function outputs the results to a CSV file
def print_to_CSV(results,output_filename):
    header = ['CVE','Plugin ID','Plugin Name','Product','Family','Published','Updated','Severity']
    f = open(output_filename,'w')
    writer = csv.writer(f)
    writer.writerow(header)
    for result in results:
        for r in result:
            writer.writerow(list(r.values()))
    f.close()
    return

# Start here
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: %s filename" % sys.argv[0])
        exit(1)
    filename = sys.argv[1]

    # Get a list of CVEs from a file
    CVEs = readfile(filename)

    # create our output filename
    output_filename = os.path.splitext(os.path.basename(filename))[0] + ".csv"
    results = []
    
    # Search for each CVE
    for cve in CVEs:
        results.append(searchForPlugin(cve.strip()))
        # We sleep for a sec to be nice
        time.sleep(1)
    
    # Results in hand, we write them to a file
    print_to_CSV(results,output_filename)
    print ("Done!")
    exit()

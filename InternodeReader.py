# -*- mode: python; -*-
import requests
#from lxml import etree
try:
    from bs4 import BeautifulSoup
except ImportError:
    from BeautifulSoup import BeautifulSoup

API_URL = "https://customer-webtools-api.internode.on.net/api/v1.5/"

class InternodeApiError (Exception):
    def __init__(self, desc):
        self.error_desc = str(desc)

    def __str__(self):
        return "Internode API error: %s.\n", self.error_desc

class InternodeNoIDError (InternodeApiError):
    pass

class InternodeAccess (object):
    def __init__(self, user, passw):
        """ Initialise the InternodeAccess object and fetch account details from Internode. """
        self.auth = user, passw
        
        self.service_type = None
        self.service_id = None
        self.service_url = None

        self.get_service_info()

    def get_service_info(self):
        """ Fill the service information variables. """
        try:
            req = requests.get(API_URL, auth=self.auth)
        except:
            print("Failed to get usage info!")
            return 0
        if req.status_code not in (200, 500):
            print("Something went wrong getting service information!")
            print("Received %d" % req.status_code)
        
        try:
            v = str(req.content)

            page = BeautifulSoup(v)
            # First service only.
            service = page.internode.services.service
            
            # Get the service information.
            self.service_url = service["href"]
            self.service_type = service["type"]
            self.service_id = service.text

        except TypeError as er:
            print(er)
            print("(Service id was " + str(self.service_id) + ")")
            self.service_id = None

    def get_today(self):
        if self.service_id == None:
            raise InternodeNoIDError("no service ID provided")
        url = API_URL + self.service_id + "/usage"
        
        req = requests.get(url, auth=self.auth)
        page = BeautifulSoup(req.content)

        # Get the current usage and quota information.
        TOTAL_QUOTA = 1
        CURRENT_QUOTA = 1
        for i in page.findAll("traffic"):
            if i["name"] == "total":
                TOTAL_QUOTA = int(i["quota"]) # Return BYTES.
                CURRENT_QUOTA = int(i.text)

        return CURRENT_QUOTA, TOTAL_QUOTA

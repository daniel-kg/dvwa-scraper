# Installing dependencies

You will need to install pipenv! https://github.com/pypa/pipenv

Then go to this repos directory on your machine and run:

    $ pipenv install

# Running
Use the '--help' argument to see help in your terminal about how to run the script:

    python scrape_and_inject_dvwa.py --help
        usage: scrape_and_inject_dvwa.py [-h] [--username USERNAME] [--password PASSWORD] [--persist-location PERSIST_LOCATION] network_address

        positional arguments:
          network_address       The network address of the DVWA server

        optional arguments:
          -h, --help            show this help message and exit
          --username USERNAME   The username used to log in to DVWA
          --password PASSWORD   The password that is used to log into DVWA
          --persist-location PERSIST_LOCATION
                                The location to store the files that allow resuming a scrape in the event of a failure. Defaults to the working directory.

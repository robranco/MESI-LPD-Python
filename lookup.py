import geoip2.database
import sys

# 1. Open the databases (Make sure the files are in the same folder!)
reader_city = geoip2.database.Reader('GeoLite2-City.mmdb')
reader_country = geoip2.database.Reader('GeoLite2-Country.mmdb')

# 2. Get the IP address from the command line
# We use [1:] to skip the script name and get the first IP
for ip in sys.argv[1:]:
    try:
        # Check Country
        response_country = reader_country.country(ip)
        country_name = response_country.country.name

        # Check City
        response_city = reader_city.city(ip)
        city_name = response_city.city.name

        # Print the result
        print(f"IP: {ip} | Country: {country_name} | City: {city_name}")

    except Exception:
        # If the IP is internal (like 127.0.0.1) or not found, skip it
        print(f"IP: {ip} | Not found in database")

# 3. Always close the readers when done
reader_city.close()
reader_country.close()


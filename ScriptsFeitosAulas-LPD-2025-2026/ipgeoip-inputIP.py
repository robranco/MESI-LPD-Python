
import geoip2.database

ip = input("Insira IP: ")
reader = geoip2.database.Reader('./GeoLite2-City-2025.mmdb')

returndata = reader.city(ip)

print (returndata.country.iso_code)
print (returndata.city.name)
print (returndata.subdivisions.most_specific.name)


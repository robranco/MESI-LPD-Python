import geoip2.database

reader = geoip2.database.Reader('./GeoLite2-City.mmdb')

returndata = reader.city("213.13.145.114")

print (returndata.country.iso_code)
print (returndata.city.name)
print (returndata.subdivisions.most_specific.name)


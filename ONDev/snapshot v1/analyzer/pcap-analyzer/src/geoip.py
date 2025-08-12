from folium import Map, Marker
import geoip2.database

def map_ip_addresses(ip_addresses):
    # Load GeoIP database
    reader = geoip2.database.Reader('path/to/GeoLite2-City.mmdb')
    
    # Create a map centered around the first IP address
    if ip_addresses:
        first_ip = ip_addresses[0]
        location = reader.city(first_ip)
        map_center = [location.location.latitude, location.location.longitude]
    else:
        map_center = [0, 0]  # Default center if no IPs are provided

    ip_map = Map(location=map_center, zoom_start=2)

    for ip in ip_addresses:
        try:
            response = reader.city(ip)
            lat = response.location.latitude
            lon = response.location.longitude
            Marker(location=[lat, lon], popup=ip).add_to(ip_map)
        except Exception as e:
            print(f"Could not find location for IP {ip}: {e}")

    reader.close()
    return ip_map
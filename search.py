import sqlite3

def search(query):
    conn = sqlite3.connect('shodan_lite.db')
    cursor = conn.cursor()

    sql = f'''
    SELECT ip, port, protocol, service, product, version
    FROM services
    WHERE ip LIKE ?
    OR service LIKE ?
    OR product LIKE ?
    OR version LIKE ?
    ORDER BY ip, port;
    '''

    wildcard = f"%{query}%"
    cursor.execute(sql, (wildcard, wildcard, wildcard, wildcard))

    results = cursor.fetchall()
    conn.close()

    if results:
        for row in results:
            print(f"{row[0]:<15} | {row[1]:<5} | {row[2]:<5} | {row[3]:<15} | {row[4]:<20} | {row[5]}")
    else:
        print("No results found.")

if __name__ == "__main__":
    query = input("🔍 Search for (IP, service, product, version): ")
    search(query)


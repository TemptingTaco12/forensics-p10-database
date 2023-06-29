def search_for_property(tx, property, value):
    query = ''' Match (n)
                where n.$property = $value
                return n
            '''
    tx.run(query, property=property, value=value)

def search_for_all_malware_types(tx):
    query = ''' Match (n:Malware_Type)
                return n
            '''
    tx.run(query)




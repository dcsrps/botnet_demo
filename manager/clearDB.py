import mysql.connector

############################
#
# Clear entries.
#
###########################

LIST_OF_TABLES= ["fim_output", "gateway_alerts","alerts"]

con = mysql.connector.connect(user='manager', password='manager', host='127.0.0.1', database='alerts')
cur = con.cursor()

for a_table in LIST_OF_TABLES:
    l_query = "delete from {}".format(a_table)
    cur.execute(l_query)
    con.commit()  

con.close()
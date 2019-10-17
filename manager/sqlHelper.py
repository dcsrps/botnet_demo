import mysql.connector
import logging
import sys

class sqliteDb(object):
    def __init__(self, db_name):
        self._con = mysql.connector.connect(user='manager', password='manager',
                              host='127.0.0.1', database=db_name)
        try:
            self._cur = self._con.cursor()
        except:
            logging.error(sys.exc_info())
        """
        CREATE TABLE alerts(
		inIP text NOT NULL,
		extIP text NOT NULL,
		proto text NOT NULL,
		appPort text NOT NULL,
		dir text NOT NULL,
        sport text NOT NULL,
		time timestamp NOT NULL,
		insize integer NOT NULL,
		outsize integer NOT NULL,
        incount integer NOT NULL,
        outcount integer NOT NULL,
        scount integer NOT NULL,
        pcount integer NOT NULL);
        """
        """
        CREATE TABLE gateway_alerts(ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP, gw text NOT NULL, count integer NOT NULL);
        """
        """
        CREATE TABLE fim_output(ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP, IoT text NOT NULL, External text NOT NULL,
         Sport text NOT NULL, Dport text NOT NULL, Traffic text NOT NULL, Meaning text NOT NULL);
        """


    def update_fim_output(self, i_in:dict):
        try:

            placeholders = ', '.join(['%s'] * len(i_in))
            columns = ', '.join(i_in.keys())
            columns = 'ts, '+columns
            sql_insert = "INSERT INTO fim_output ( %s ) VALUES (NOW(), %s )" % (columns, placeholders)

            
            sql_select = "SELECT ts from fim_output where "
            for k,v in i_in.items():
                sql_select+="{}='{}' AND ".format(k, v)

            self._cur.execute(sql_select[:-4])
            
            l_op = self._cur.fetchone()
            if l_op is None:    
                self._cur.execute(sql_insert, tuple(i_in.values()))
                self._con.commit()  
            
        except:
            logging.error('update_fim_output failed.')
            logging.error(sys.exc_info())    

    def insert_gw_count(self, i_gateway, i_count):
        try:
            self._cur.execute("insert into gateway_alerts values(NOW(), %s, %s)",tuple((i_gateway, i_count)))
            self._con.commit()  
        except:
            logging.error('Insert failed for gw_count.')
            logging.error(sys.exc_info())

    def get_count(self):
        try:
            self._con.cursor().execute("SELECT count(*) FROM alerts")	
            return self._cur.fetchone()[0]
        except:
            logging.error('Query failed:{}'.format("SELECT count(*)"))
            logging.error(sys.exc_info())
            return False
    
    def insert_db(self, i_key, i_value):
        try:
            l_item = tuple(i_key.split(','))+(i_value['time'], i_value['insize'], i_value['outsize'] , i_value['incount'],\
                 i_value['outcount'],i_value['scount'], i_value['pcount'])
            self._cur.execute("INSERT INTO alerts VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", tuple(l_item))
            self._con.commit()  
            return True
        except:
            logging.error('Insert failed key:{}, value:{}.'.format(i_key, i_value))
            logging.error(sys.exc_info())
            return False
    

    def delete_db(self, i_key):
        try:
            l_item = tuple(i_key.split(','))
            self._cur.execute("""DELETE FROM alerts WHERE inIP = %s AND extIP = %s AND proto = %s AND appPort = %s AND dir = %s""", tuple(l_item))	
            self._con.commit()		
            self.db_size = self.db_size - 1
            return True
        except:
            logging.error('Delete failed key:{}'.format(i_key))
            logging.error(sys.exc_info())
            return False


    def lookup_key(self, i_key):
        try:
            l_item = tuple(i_key.split(','))
            self._cur.execute("""SELECT * FROM alerts WHERE inIP = %s AND extIP = %s AND proto = %s AND appPort = %s AND dir = %s""", tuple(l_item))	
            if len(self._cur.fetchall()):
                return True
            else:
                return False
        except:
            logging.error('Lookup failed key:{}'.format(i_key))
            logging.error(sys.exc_info())
            return False


    def update_key(self, i_key, i_value):
        try:
            l_item = tuple(i_key.split(','))
    
            self._cur.execute("""SELECT * FROM alerts WHERE inIP = %s AND extIP = %s AND proto = %s\
                 AND appPort = %s AND dir = %s AND sport = %s""", tuple(l_item))
           
    
            l_op = self._cur.fetchone()
    
            if not l_op is None:                
                l_item =  (i_value['time'], int((i_value['insize']+l_op[-6])/2), int((i_value['outsize']+l_op[-5])/2),int((i_value['incount']+l_op[-4])/2),\
                     int((i_value['outcount']+l_op[-3])/2),int((i_value['scount']+l_op[-2])/2), int((i_value['pcount']+l_op[-1])/2)) + tuple(i_key.split(','))
                self._cur.execute("""UPDATE alerts SET time=%s,insize=%s,outsize=%s,incount=%s,outcount=%s,scount=%s, pcount=%s\
                     WHERE inIP=%s AND extIP=%s AND proto=%s AND appPort=%s AND dir=%s AND sport = %s""", tuple(l_item)) 
                self._con.commit()
                return True
            else:
                logging.debug('Inserting key {}.'.format(i_key))
                self.insert_db(i_key, i_value)
        except:
            logging.error('Update failed key:{}, value:{}.'.format(i_key, i_value))
            logging.error(sys.exc_info())
            return False
    

    def lookup_other(self, i_key, i_value):
        try:        
            temp_string  = "SELECT * FROM alerts WHERE "

            for k in i_key:
                temp_string += k+' = %s AND '
        
            temp_string = temp_string[:-4]
            self._cur.execute(temp_string,tuple(i_value))
            return self._cur.fetchall()
        except:
            logging.error('lookup_other failed key:{}, value:{}'.format(i_key, i_value))
            logging.error(sys.exc_info())
            return None


    def lookup_timed_entries(self, i_time):
        try:
            if not i_time is None:

                temp_string  = "SELECT * FROM alerts WHERE time >= {}".format(i_time)
            else:
                #temp_string  = 'SELECT DISTINCT inIP, extIP, proto, appPort, dir, inSize, inCount, outSize, outCount FROM alerts where FROM_UNIXTIME(time) > "2019-08-22 15:10:51.733480"'
                temp_string  = 'select distinct inIP, extIP, proto, appPort, dir, sport, insize/incount, outsize/outcount from alerts'

            self._cur.execute(temp_string)
            return self._cur.fetchall()
        except:
            logging.error('lookup_timed_entries failed for time:{}'.format(i_time))
            logging.error(sys.exc_info())
            return None
	
    def drop_table(self):
        self._cur.execute("DROP TABLE alerts")

    def db_close(self):
        self._con.close()
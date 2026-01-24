import os
import sqlite3

dbName = "sniff.db"

#Verifica se base de dados existe
#dbIsNew = not os.path.exists(dbName)

#Ligacao/Criacao da base de dados
conn=sqlite3.connect(dbName)

#if dbIsNew:
#        print "Base dados criado com sucesso"
#else:
#        print "Base dados ja existente"

sql = """create table sniff (
    id           integer primary key autoincrement not null,
    attackid     integer default 1,
    srcip      text,
    dstip       text,
    srcmac      text,
    dstmac      text,
    timestamp   text);"""

#Executa o codigo SQL e cria a tabela sniff
#conn.executescript(sql)

conn.execute("""insert into sniff(attackid,srcip, dstip,timestamp) values (133,'12.2.2.1','22.2.2.1','Feb 25 10:38:19') """)


conn.commit()
conn.close()

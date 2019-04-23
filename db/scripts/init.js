db.createUser(
   {
     user: "hw",
     pwd: "paassword",
     roles: [ { role: "readWrite", db: "hot_wifi" } ],
     mechanisms: [ "SCRAM-SHA-1" ]
   }
);
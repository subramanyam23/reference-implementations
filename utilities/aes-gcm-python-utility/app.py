import encryption_util
import key_util
import builtins


if __name__=="__main__":
    println=builtins.print
    keypair1=key_util.generate_key_pair()
    keypair2=key_util.generate_key_pair()
      
    shared_key1=key_util.generate_shared_key(keypair1.private_key,keypair2.public_key)
    shared_key2=key_util.generate_shared_key(keypair2.private_key,keypair1.public_key)
    println("shared_key1:",shared_key1)
    println("shared_key2:",shared_key2)
    println("shared_key1==shared_key2 ==>",shared_key1==shared_key2)
    
    
    raw_data = "Hello This is ONDC Test Data"
    
    println("-----------------------------------------------")
    # encrypted_data=encryption_util.encrypt_data(shared_key1,raw_data)
    # println("Encrypted Data ===> ", encrypted_data)
    println("-----------------------------------------------")
    
    encrypted_data="eyJlbmNyeXB0ZWRfZGF0YSI6IjJ0RW1mNkJWOUl2NjNqaExickV4M1JyNyIsImhtYWMiOiJDZkxxVHJKZDZkUll5cTVjV2VIVldBPT0iLCJub25jZSI6Im0wSEZQN0RTSWIySzNrU1kifQ=="
    shared_key2="i6HWpKPkvGfQEkCDkHzzY1Ozf8e7qemY8LCjk16k9Tg="
    decrypted_data=encryption_util.decrypt_data(shared_key2,encrypted_data)
    println("decrypted Data ===> ",decrypted_data)
    println("-----------------------------------------------")


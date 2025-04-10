sudo apt install git
git clone https://github.com/morrownr/8821au-20210708.git
sudo dkms add ./8821au-20210708
sudo dkms install rtl8821au/5.12.5.2
reboot
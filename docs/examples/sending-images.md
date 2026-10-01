# Sending images

## Sending images to different recipients
Imagine you have a directory full of PNG files, containg info for respective domain administrators.

```
example.com.png
example.com-2.png
wikipedia.org.png
csirt.cz.png
```

We want to send two images to the admin of `example.com` and single one for `wikipedia.org` and `csirt.cz`. First, create a CSV having first column the domain name and second the respective image. To do so, we use the [pz](https://github.com/CZ-NIC/pz) library.

```
pip3 install pz  # install `pz` if needed
ls *.png | pz 're.sub("-\d+$", "", Path(s).stem),s' > domains_images.csv
```

CSV domains_images.csv now looks like this:

```
example.com	example.com-2.png
example.com	example.com.png
wikipedia.com	wikipedia.com.png
csirt.cz	csirt.cz.png
```

The following command will tell `convey` to add an e-mail column derived from the hostname and when sending files, attach all our images from the path column.

```
convey domains_images.csv  -t hostname,path -f abusemail --split abusemail --attach-files False  --attach-paths-from-path-column True
```

Wizzard will lead you to sending the test mail to you own address. This is the sending a testing e-mail dialog for the `wikipedia.org` domain.

```
Attachment wikipedia.com.png (image/png): PNG...
MIME-Version: 1.0
Subject: PNG that might interest you
To: abuse@wikimedia.org
Date: Fri, 06 Jan 2023 20:04:31 +0100

Body text message
Testing e-mail address to be sent to – type in or hit Enter to use your-testing-mail@example.com (Ctrl+C to go back):

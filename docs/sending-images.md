# Sending images

Attach arbitrary files to the e-mails, not only the split CSV chunks.

## Sending images to different recipients
Imagine you have a directory full of PNG files, containing info for respective domain administrators.

```
example.com.png
example.com-2.png
wikipedia.org.png
csirt.cz.png
```

We want to send two images to the admin of `example.com` and single one for `wikipedia.org` and `csirt.cz`. First, create a CSV having the domain name in the first column and the respective image in the second. To do so, we use the [pz](https://github.com/CZ-NIC/pz) library.

```bash
pip3 install pz  # install `pz` if needed
ls *.png | pz 're.sub(r"-\d+$", "", Path(s).stem),s' > domains_images.csv
```

CSV domains_images.csv now looks like this:

```
example.com	example.com-2.png
example.com	example.com.png
wikipedia.org	wikipedia.org.png
csirt.cz	csirt.cz.png
```

The following command tells `convey` the column types (`--type hostname,path`), adds an abuse e-mail column derived from the hostname, splits by it and, when sending, attaches the images from the path column instead of the split CSV.

```bash
$ convey domains_images.csv -t hostname,path -f abusemail --split abusemail --attach-files False --attach-paths-from-path-column True
```

The wizard will lead you to sending the test mail to your own address. This is the sending a testing e-mail dialog for the `wikipedia.org` domain.

```
Attachment wikipedia.org.png (image/png): PNG...
MIME-Version: 1.0
Subject: PNG that might interest you
To: abuse@wikimedia.org
Date: Fri, 06 Jan 2023 20:04:31 +0100

Body text message
Testing e-mail address to be sent to – type in or hit Enter to use your-testing-mail@example.com (Ctrl+C to go back):
```

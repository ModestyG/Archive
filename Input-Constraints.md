
# Input Constraints #

This document contains all the constraints and additional info about any data that a user can modify directly. This can be to improve UX, prevent bugs, or prevent attacks. Since this document is meant to be used by developers, there should both be info about what values the user is able to enter themselves, as well as any additional processing that data has to go through before it can be allowed in the db.

## User Info ##

Fields provided or generated when a user is created

### Password ###

*Required*

Length: 12 - &infin;

### Username ###

*Required*

Length: 3 - 20

Allowed characters:
- Letters: a-z, A-Z
- Numbers: 0-9
- Special: - _ .
OBS: Space not included in list of allowed characters

Special constraints:
- Has to be unique
- Cannot be entirely numeric

### Email ###

*Required*

Length: 1 - 64 (Will have to be longer than 1 to fulfill other requirements but there is no specific minlength)

Has to be unique

All other constraints are provided in validators.email. See that function for more information.

## Posts ##

Information provided or generated when a new post is created

### Title ###

Length: < 128

All tags that are not in the list below should go through sanitization. They can still be part of the title but should not be registered as HTML  
Allowed HTML tags:  
- `<b> </b>`
- `<i> </i>`
- `<u> </u>`
- `<em> </em>`
- `<strong> </strong>`
- `<a href="" title="" target=""> </a>`

OBS: Either Title or Content is *Required*, but you do not need to have both

### Content ###

Length: < 2048

All tags that are not in the list below should go through sanitization. They can still be part of the content but should not be registered as HTML  
Allowed HTML tags:  
- `<b> </b>`
- `<i> </i>`
- `<u> </u>`
- `<em> </em>`
- `<strong> </strong>`
- `<a href="" title="" target=""> </a>`

OBS: Either Title or Content is *Required*, but you do not have to have both

### Tag ###

Length: < 64  
Total Length: < 2048 (This is the maximum total length of all tags on a single post)

Tags should be sanitized in such a way that no HTML tags are allowed. They can still be part of the posts tags but should not be registered as HTML 



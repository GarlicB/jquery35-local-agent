jQuery runtime assets bundled for offline automation.

Files:
- jquery-3.5.1.min.js
- jquery-migrate-3.6.0.min.js

Source:
- https://code.jquery.com/jquery-3.5.1.min.js
- https://code.jquery.com/jquery-migrate-3.6.0.min.js

License:
- jQuery and jQuery Migrate are distributed under the MIT license.
- The minified file headers point to jquery.org/license and jquery.com/license.

Purpose:
- patch-jquery mode copies these files into the TO-BE web root when the target
  does not already contain the configured jQuery core/Migrate files.

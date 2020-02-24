var gulp = require("gulp");
var postcss = require("gulp-postcss");
var autoprefixer = require("autoprefixer");
var flex_fixes = require("postcss-flexbugs-fixes");
var calcs = require("postcss-calc");
var comments = require("postcss-discard-comments");
var pixrem = require("pixrem");
var vmin = require("postcss-vmin");
var preset = require("postcss-preset-env");
var mqpacker = require("css-mqpacker");

gulp.task("css", function() {
  var plugins = [
    mqpacker,
    autoprefixer({ overrideBrowserslist: ["> 0.1%"], cascade: false }),
    flex_fixes,
    calcs,
    pixrem,
    vmin,
    preset({ stage: 0 }),
    comments
  ];
  return gulp
    .src("public/*.css")
    .pipe(postcss(plugins))
    .pipe(gulp.dest("public/"));
});

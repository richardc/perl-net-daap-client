use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'      => 'dapple',
    'VERSION'	=> 0.21,
    'PREREQ_PM' => { LWP => 0 }, 

    ## Add these new keywords supported since 5.005
    ($] >= 5.005 ?
      (ABSTRACT => 'DAAP library for Perl',
       AUTHOR     => 'Nathan Torkington <nathan AT torkington.com>') : ()
    ),
);

<?php

    //    Index Parameters
        $string='INSERT INTO stuff(name,value) VALUES (?,?)';
        $data=array('Fred',23);

    //    Named Parameters
        $string='INSERT INTO stuff(name,value) VALUES (:name,:value)';
        $data=array('name'=>'Fred','value'=>23);

    print parms($string,$data);

    ?>
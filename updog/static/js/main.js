$(document).ready(function () {
	$('#tableData').DataTable({
		"paging" : false,
		"responsive" : {
			"details" : false
		},
		"dom": "lrtip",
		"language" : {
		    "info" : "_TOTAL_ items",
		},
		"columnDefs" : [
			{"targets" : 0, "orderable" : false},
			{"targets" : 4, "orderable" : false},
			{"orderSequence" : [ "desc", "asc" ], "targets": [ 1 ]}
		],
		order: [[ 1, "asc" ]]
	});
});

function killServer(){
    if(confirm('Are you sure you want to terminate the updog server?'))
        window.location.href='/?stop';
}

var inputs = document.querySelectorAll( '.uploadFile' );

Array.prototype.forEach.call( inputs, function( input )
{
	var label	 = input.nextElementSibling,
		labelVal = label.innerHTML;

	input.addEventListener( 'change', function( e )
	{
		var fileName = '';
		if( this.files && this.files.length > 1 )
			fileName = ( this.getAttribute( 'data-multiple-caption' ) || '' ).replace( '{count}', this.files.length );
		else {
			fileName = e.target.value.split("\\").pop();
		}

		if( fileName )
			label.querySelector( 'span' ).innerHTML = fileName;
		else
			label.innerHTML = labelVal;
	});
});

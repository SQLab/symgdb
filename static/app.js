// Connect to websocket server
var host = window.location.host;
var ws = new WebSocket('ws://'+host+'/ws');

Vue.component('trace',{
	props: ['item'],
	template: '<div class="col-1" @click="$root.updateTrace(item.id)">{{item.id}}</div>'
})

Vue.component('traces',{
	props: ['items'],
	template: '<div><trace v-for="item in items" :key=item.id :item=item></trace></div>'
})

Vue.component('assembly',{
	props: ['assembly'],
	template: '<div class="col-5">{{assembly}}</div>'
})

Vue.component('register',{
	props: ['register'],
	template: '<div class="col-5">{{register}}</div>'
})

new Vue({
	el: '#app',
	data: {
		items: [
		],
		assembly:{},
		register:{}
	},
	created: function(){
		Vue.http.get("/traces/count").then(response => {
			body = response.body
				console.log(body)
				this.items = new Array(parseInt(body)).join().split(',').map(function(item, index){ return {id: index};})
		}, response => {
		})

		Vue.http.get("/traces/1").then(response => {
			this.assembly = response.body.assemblys;
			this.register = response.body.registers;
		}, response => {
		})
	},
	methods: {
		updateTrace: function (id){
			Vue.http.get("/traces/"+id).then(response => {
				this.assembly = response.body.assemblys;
				this.register = response.body.registers;
			}, response => {
			})
		}
	}
})

ws.onopen = function(){
	console.log("Connected to server")
};

ws.onmessage = function(message){
	console.log(message.data)
		//data = JSON.parse(message.data);
		//assembly.assembly = data;
};

ws.onclose = function(){
	console.log("Disconnected from server");
};

ws.onerror = function(error){
	console.log(error);
};

<template>
		<div id="app">
				<nav class="navbar navbar-inverse bg-inverse">
					<a class="navbar-brand">qisa</a>
				</nav>
				<div class="container-fluid">
					<div class="row">
						<traces :items=items>
						</traces>
						<assembly :assembly="assembly">
						</assembly>
						<register :register="register">
						</register>
					</div>
				</div>
				<log></log>
				<console></console>
		</div>
</template>

<script>
import Traces from './components/Traces.vue'
import Assembly from './components/Assembly.vue'
import Register from './components/Register.vue'
import Log from './components/Log.vue'
import Console from './components/Console.vue'
export default {
	name: 'App',
  data: () => {
  return {
    items: [
    ],
    assembly: {},
    register: {}
  }
  },
	components: {
		'traces': Traces,
		'assembly': Assembly,
		'register': Register,
		'log': Log,
		'console': Console
	}
}
</script>

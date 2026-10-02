"""rclpy nodes. NOT run against a real ROS 2 install (none was available); only py_compile checked."""
import time
import rclpy
from rclpy.node import Node
from atep_msgs.msg import Envelope
from .verifier import EnvelopeReceiver


def topic_for(fleet, unit, cls):
    return f"/fleet/{fleet}/{unit}/{cls}"          # same convention as the MQTT example


class EnvelopePublisher(Node):
    """Re-publishes envelope bytes produced elsewhere (for example `atep sign` then `atep encrypt`)."""

    def __init__(self, envelope_bytes, fleet, unit, cls, period=1.0):
        super().__init__("atep_envelope_publisher")
        self.pub = self.create_publisher(Envelope, topic_for(fleet, unit, cls), 10)
        self.msg = Envelope(envelope=list(envelope_bytes), command_class=cls, sender_hint="", suite="ATEP-1")
        self.create_timer(period, lambda: self.pub.publish(self.msg))


class EnvelopeSubscriber(Node):
    def __init__(self, receiver: EnvelopeReceiver, fleet, unit, cls):
        super().__init__("atep_envelope_subscriber")
        receiver.clock = receiver.clock or (lambda: int(time.time()))
        receiver.on_accept = lambda r, m: self.get_logger().info(f"accepted {r['command_class']} from {r['signer']}")
        receiver.on_reject = lambda r, m: self.get_logger().warning(f"rejected at step {r['step']}: {r['error']}")
        self.create_subscription(Envelope, topic_for(fleet, unit, cls), receiver.handle, 10)


def spin(node):
    rclpy.init()
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        rclpy.shutdown()
